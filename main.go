// P2P stub host: grpc control plane + TCP bridge data plane.
//
// The GOST side calls OpenTunnel(peer) over gRPC; the stub responds with a
// local TCP endpoint that bridges to the peer address. This milestone only
// proves the plugin seam — no NAT traversal, rendezvous, or encryption.
package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/go-gost/p2p/internal/derpclient"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "gRPC listen address (control plane)")
	bind := flag.String("bind", "127.0.0.1", "data plane listen IP; each tunnel gets an ephemeral port on it")
	token := flag.String("token", "", "control-plane auth token; empty disables checking (loopback default)")
	derpURL := flag.String("derp", "", "DERP relay server URL (wss://host/derp); enables DERP engine mode")
	keyFile := flag.String("key", "", "curve25519 private key file for DERP mode (hex); created if missing")
	target := flag.String("target", "", "local bridge target for inbound tunnels in DERP mode (host:port)")
	var forwards []string
	flag.Func("forward", `static port forward "listen-addr=peer-key" (repeatable; DERP mode)`, func(v string) error {
		forwards = append(forwards, v)
		return nil
	})
	stunAddr := flag.String("stun", "", "STUN server address (host:port) for direct hole punching; empty disables direct (relay only)")
	tlsSecure := flag.Bool("tls.secure", true, "verify the relay's TLS certificate (set false to trust any cert)")
	tlsCAFile := flag.String("tls.caFile", "", "PEM CA file to trust the relay's self-signed certificate")
	logLevel := flag.String("log.level", "info", "log level: trace, debug, info, warn, error, or fatal")
	logFormat := flag.String("log.format", "json", "log format: json or text")
	logOutput := flag.String("log.output", "stderr", "log output: stderr, stdout, none, or a file path")
	flag.Parse()

	if err := setupLogger(*logOutput, *logFormat, *logLevel); err != nil {
		slog.Error("setup logger", "error", err)
		os.Exit(1)
	}

	var engine *Engine
	if *derpURL != "" {
		priv, pub, err := loadOrCreateKey(*keyFile)
		if err != nil {
			slog.Error("load key", "file", *keyFile, "error", err)
			os.Exit(1)
		}
		if *target != "" {
			if _, _, err := net.SplitHostPort(*target); err != nil {
				slog.Error("invalid --target", "value", *target, "error", err)
				os.Exit(1)
			}
		}
		engine = newEngine(*derpURL, *target, priv, slog.Default())
		// Hole punching is opt-in: only attempt a direct path when the user
		// explicitly sets --stun. Empty stunAddr keeps traffic on the relay.
		engine.stunAddr = *stunAddr
		engine.tlsCfg = buildTLSConfig(*tlsSecure, *tlsCAFile)
		slog.Info("p2p derp engine", "url", *derpURL,
			"pubkey", base64.RawURLEncoding.EncodeToString(pub[:]),
			"target", *target)
		if err := engine.Connect(); err != nil {
			// Keep serving gRPC: the reconnect ticker retries in the
			// background, but inbound tunnels stay unreachable until the
			// first successful connection.
			slog.Warn("derp connect", "error", err)
		}
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("listen", "addr", *addr, "error", err)
		os.Exit(1)
	}

	// authInterceptor enforces --token on every RPC via the "token" gRPC
	// metadata key sent by the GOST client (x/internal/plugin per-RPC
	// credentials). Empty --token disables checking: the loopback default
	// remains the only boundary, so keep --addr off-loopback unless both
	// --token and control TLS are in place.
	svr := newServer(*bind, engine)
	for _, spec := range forwards {
		if err := svr.addForward(spec); err != nil {
			slog.Error("forward", "spec", spec, "error", err)
			os.Exit(1)
		}
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(*token)))
	proto.RegisterP2PServer(s, svr)
	slog.Info("p2p stub listening", "addr", *addr, "bind", *bind, "auth", *token != "", "derp", *derpURL != "")
	if err := s.Serve(ln); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

// Custom slog levels to cover gost's logrus-compatible range (slog built-in:
// Debug=-4, Info=0, Warn=4, Error=8).
const (
	levelTrace = slog.Level(-8)
	levelFatal = slog.Level(12)
)

// setupLogger configures the default slog logger mirroring gost's logger
// config: output (stderr/stdout/none/file), level (trace…fatal), and format
// (json/text, JSON by default). File output is rotation-backed via lumberjack,
// the same writer gost uses.
func setupLogger(output, format, level string) error {
	lvl, err := parseLogLevel(level)
	if err != nil {
		return err
	}

	w, err := logOutput(output)
	if err != nil {
		return err
	}

	ho := &slog.HandlerOptions{
		Level:       lvl,
		ReplaceAttr: replaceAttr,
		// Attach the caller file:line so debug/trace logs can be located
		// (matching gost's reportcaller behavior when running verbose).
		AddSource: lvl <= slog.LevelDebug,
	}
	var h slog.Handler
	switch format {
	case "", "json":
		h = slog.NewJSONHandler(w, ho)
	case "text":
		h = slog.NewTextHandler(w, ho)
	default:
		return fmt.Errorf("unknown log format %q (want json or text)", format)
	}
	slog.SetDefault(slog.New(h))
	return nil
}

// parseLogLevel maps a gost-style level name to a slog.Level.
func parseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace":
		return levelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "fatal":
		return levelFatal, nil
	default:
		return 0, fmt.Errorf("unknown log level %q (want trace, debug, info, warn, error, or fatal)", s)
	}
}

// logOutput resolves an output destination to a writer. A file path returns a
// lumberjack writer for size-based rotation.
func logOutput(output string) (io.Writer, error) {
	switch output {
	case "", "stderr":
		return os.Stderr, nil
	case "stdout":
		return os.Stdout, nil
	case "none", "null":
		return io.Discard, nil
	default:
		if dir := filepath.Dir(output); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
		}
		// ponytail: rotation knobs (maxSize/maxBackups/maxAge/compress) are not
		// exposed as flags; lumberjack defaults (100MB, keep all) are fine.
		return &lumberjack.Logger{Filename: output, MaxSize: 100}, nil
	}
}

// replaceAttr normalises slog output to gost's logrus-style form: lowercase
// level names and RFC 3339 timestamps with millisecond precision.
func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		if t, ok := a.Value.Any().(time.Time); ok {
			a.Value = slog.StringValue(t.Format("2006-01-02T15:04:05.000Z07:00"))
		}
	case slog.LevelKey:
		if lvl, ok := a.Value.Any().(slog.Level); ok {
			a.Value = slog.StringValue(levelString(lvl))
		}
	case slog.SourceKey:
		// Replace slog's nested source object with a gost-style flat "caller"
		// of the form dir/file.go:line (only present when AddSource is on,
		// i.e. running at debug/trace).
		if s, ok := a.Value.Any().(*slog.Source); ok {
			caller := filepath.Join(filepath.Base(filepath.Dir(s.File)), filepath.Base(s.File))
			a = slog.String("caller", fmt.Sprintf("%s:%d", caller, s.Line))
		}
	}
	return a
}

// levelString returns a gost-style lowercase level name for a slog.Level.
func levelString(lvl slog.Level) string {
	switch {
	case lvl <= levelTrace:
		return "trace"
	case lvl <= slog.LevelDebug:
		return "debug"
	case lvl <= slog.LevelInfo:
		return "info"
	case lvl <= slog.LevelWarn:
		return "warn"
	case lvl <= slog.LevelError:
		return "error"
	default:
		return "fatal"
	}
}

// buildTLSConfig mirrors gost's TLS dialer options for the relay connection:
// secure=false skips certificate verification (InsecureSkipVerify), caFile
// adds a PEM CA (e.g. the relay's self-signed cert) to the trusted roots.
// Returns nil when defaults suffice (secure, no CA) so derpclient uses Go's
// normal verification.
func buildTLSConfig(secure bool, caFile string) *tls.Config {
	if secure && caFile == "" {
		return nil
	}
	cfg := &tls.Config{InsecureSkipVerify: !secure}
	if caFile != "" {
		data, err := os.ReadFile(caFile)
		if err != nil {
			slog.Error("load CA", "file", caFile, "error", err)
			return cfg
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			slog.Error("load CA", "file", caFile, "error", "no PEM certificates found")
			return cfg
		}
		cfg.RootCAs = pool
	}
	return cfg
}

// defaultKeyPath is where the DERP key lives unless --key overrides it.
func defaultKeyPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "p2p", "key-v1")
	}
	return "p2p-key-v1"
}

// loadOrCreateKey loads a hex-encoded curve25519 private key from path,
// generating and storing a new one (0600) if the file is missing.
func loadOrCreateKey(path string) (derpclient.PrivateKey, derpclient.PublicKey, error) {
	if path == "" {
		path = defaultKeyPath()
	}
	if b, err := os.ReadFile(path); err == nil {
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return derpclient.PrivateKey{}, derpclient.PublicKey{}, fmt.Errorf("bad key file: %w", err)
		}
		var priv derpclient.PrivateKey
		if len(raw) != len(priv) {
			return priv, derpclient.PublicKey{}, fmt.Errorf("bad key file: want %d hex bytes, got %d", len(priv), len(raw))
		}
		copy(priv[:], raw)
		return priv, priv.Public(), nil
	}
	priv, pub, err := derpclient.Generate()
	if err != nil {
		return priv, pub, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return priv, pub, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv[:])+"\n"), 0o600); err != nil {
		return priv, pub, err
	}
	return priv, pub, nil
}

// authInterceptor returns a unary interceptor comparing the client's token
// metadata against want. Constant-time compare; an absent token never matches.
func authInterceptor(want string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if want != "" {
			got := ""
			if md, ok := metadata.FromIncomingContext(ctx); ok && len(md["token"]) > 0 {
				got = md["token"][0]
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return nil, status.Error(codes.Unauthenticated, "invalid token")
			}
		}
		return handler(ctx, req)
	}
}
