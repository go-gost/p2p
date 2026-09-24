// Command p2p runs a p2p endpoint standalone: it builds the endpoint from a
// config file and flags, and serves it over the gRPC control plane so a GOST
// plugin client can open tunnels to it. The library is the importable
// "github.com/go-gost/p2p" module; this command is only the flag/config front
// end around it.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/endpoint"
	"github.com/go-gost/p2p/grpc"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {
	// Flags are overrides on top of the config file; their defaults are only
	// used as a fallback when neither the config nor the flag sets the value.
	addr := flag.String("addr", "", "gRPC listen address (control plane); empty runs none — a --target/--forward node has no GOST client to serve")
	token := flag.String("token", "", "control-plane auth token; empty disables checking (loopback default)")
	derpURL := flag.String("derp", "", "DERP relay server URL (wss://host/derp); enables DERP engine mode")
	keyFile := flag.String("key", "", "curve25519 private key file for DERP mode (hex); created if missing")
	var targets []string
	flag.Func("target", `inbound bridge target (repeatable; "host:port" = tcp, "udp://host:port" = udp; DERP mode)`, func(v string) error {
		targets = append(targets, v)
		return nil
	})
	var forwards []string
	flag.Func("forward", `static port forward "listen-addr=peer-key" (repeatable; DERP mode)`, func(v string) error {
		forwards = append(forwards, v)
		return nil
	})
	stunAddr := flag.String("stun", "", "STUN server address (host:port) for the IPv4 direct path; IPv6 is independent of STUN")
	direct := flag.Bool("direct", true, "attempt a direct (hole-punched) path; false forces relay-only")
	tlsSecure := flag.Bool("tls.secure", true, "verify the relay's TLS certificate (set false to trust any cert)")
	tlsCAFile := flag.String("tls.caFile", "", "PEM CA file to trust the relay's self-signed certificate")
	logLevel := flag.String("log.level", "info", "log level: trace, debug, info, warn, error, or fatal")
	logFormat := flag.String("log.format", "json", "log format: json or text")
	logOutput := flag.String("log.output", "stderr", "log output: stderr, stdout, none, or a file path")
	configFile := flag.String("C", "", "config file (YAML)")
	flag.Parse()

	// Record which flags were explicitly set so they override the config.
	set := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// The config is the single source of truth; flags only override it.
	cfg := &config{}
	if *configFile != "" {
		c, err := loadConfig(*configFile)
		if err != nil {
			slog.Error("load config", "file", *configFile, "error", err)
			os.Exit(1)
		}
		cfg = c
	}

	// Defaults for anything the config didn't set, so the flag overrides below
	// never dereference a nil. The endpoint applies its own TLS/Direct defaults.
	if cfg.TLS == nil {
		cfg.TLS = &p2p.TLSConfig{}
	}
	if cfg.Log == nil {
		cfg.Log = &logConfig{}
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if cfg.Log.Format == "" {
		cfg.Log.Format = "json"
	}
	if cfg.Log.Output == "" {
		cfg.Log.Output = "stderr"
	}

	// Explicitly-set flags override the config.
	if set["addr"] {
		cfg.Addr = *addr
	}
	if set["token"] {
		cfg.Token = *token
	}
	if set["derp"] {
		cfg.Derp = *derpURL
	}
	if set["key"] {
		cfg.Key = *keyFile
	}
	if set["stun"] {
		cfg.Stun = *stunAddr
	}
	if set["direct"] {
		cfg.Direct = direct
	}
	if set["tls.secure"] {
		cfg.TLS.Secure = tlsSecure
	}
	if set["tls.caFile"] {
		cfg.TLS.CAFile = *tlsCAFile
	}
	if set["log.level"] {
		cfg.Log.Level = *logLevel
	}
	if set["log.format"] {
		cfg.Log.Format = *logFormat
	}
	if set["log.output"] {
		cfg.Log.Output = *logOutput
	}

	// Merge the repeatable flags into the config. Targets are additive (the
	// engine parses them, so a malformed spec fails startup loudly); the scalar
	// Target is normalized into Targets so it is not counted twice.
	if len(targets) > 0 || cfg.Target != "" {
		cfg.Targets = append(cfg.TargetList(), targets...)
		cfg.Target = ""
	}
	for _, spec := range forwards {
		listen, peer, ok := strings.Cut(spec, "=")
		if !ok || listen == "" || peer == "" {
			slog.Error("forward", "spec", spec, "error", `want "listen-addr=peer-key"`)
			os.Exit(1)
		}
		cfg.Forwards = append(cfg.Forwards, p2p.ForwardConfig{Listen: listen, Peer: peer})
	}

	// Set up the logger from the resolved config before creating the endpoint.
	if err := setupLogger(cfg.Log.Output, cfg.Log.Format, cfg.Log.Level, cfg.Log.Rotation); err != nil {
		slog.Error("setup logger", "error", err)
		os.Exit(1)
	}

	ep, err := endpoint.New(&cfg.Config, endpoint.WithLogger(slog.Default()))
	if err != nil {
		slog.Error("init", "error", err)
		os.Exit(1)
	}
	if cfg.Derp != "" {
		slog.Info("p2p derp engine", "url", cfg.Derp,
			"pubkey", ep.PublicKey(), "targets", cfg.Targets)
	}
	// The control plane exists for a GOST client (a p2ps plugin) to open tunnels
	// through this node. A node that only bridges inbound traffic (--target) or
	// forwards static ports has no such client, and an address nothing dials is
	// just a local port: it stays closed unless one is asked for.
	var srv *grpc.Server
	if controlPlaneOff(cfg.Addr) {
		slog.Info("p2p control plane off",
			"hint", "pass --addr to serve a GOST client's OpenTunnel()")
	} else {
		var err error
		srv, err = grpc.New(ep, grpc.WithAddr(cfg.Addr), grpc.WithToken(cfg.Token))
		if err != nil {
			slog.Error("init", "error", err)
			ep.Close()
			os.Exit(1)
		}
		if _, err := srv.Start(); err != nil {
			slog.Error("start", "error", err)
			srv.Close()
			ep.Close()
			os.Exit(1)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if srv != nil {
		srv.Close()
	}
	ep.Close()
}

// controlPlaneOff reports whether no control plane is wanted: an unset address,
// or an explicit "off"/"none" (so a config file can say it in a word).
func controlPlaneOff(addr string) bool {
	switch strings.ToLower(strings.TrimSpace(addr)) {
	case "", "off", "none":
		return true
	}
	return false
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
func setupLogger(output, format, level string, rot *logRotationConfig) error {
	lvl, err := parseLogLevel(level)
	if err != nil {
		return err
	}

	w, err := logOutput(output, rot)
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
// lumberjack writer for size-based rotation; rot (the log.rotation config)
// overrides lumberjack's defaults.
func logOutput(output string, rot *logRotationConfig) (io.Writer, error) {
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
		l := &lumberjack.Logger{Filename: output}
		if rot != nil {
			l.MaxSize = rot.MaxSize
			l.MaxAge = rot.MaxAge
			l.MaxBackups = rot.MaxBackups
			l.LocalTime = rot.LocalTime
			l.Compress = rot.Compress
		}
		return l, nil
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
