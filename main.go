// P2P stub host: grpc control plane + TCP bridge data plane.
//
// The GOST side calls OpenTunnel(peer) over gRPC; the stub responds with a
// local TCP endpoint that bridges to the peer address. This milestone only
// proves the plugin seam — no NAT traversal, rendezvous, or encryption.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"p2p/internal/derpclient"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "gRPC listen address (control plane)")
	bind := flag.String("bind", "127.0.0.1", "data plane listen IP; each tunnel gets an ephemeral port on it")
	token := flag.String("token", "", "control-plane auth token; empty disables checking (loopback default)")
	derpURL := flag.String("derp", "", "DERP relay server URL (wss://host/derp); enables DERP engine mode")
	keyFile := flag.String("key", "", "curve25519 private key file for DERP mode (hex); created if missing")
	target := flag.String("target", "", "local bridge target for inbound tunnels in DERP mode (host:port)")
	var services stringList
	flag.Var(&services, "service", "service name to announce (repeatable); enables name-based discovery for this host")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	if *debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
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
		engine = newEngine(*derpURL, *target, priv, services, slog.Default())
		slog.Info("p2p derp engine", "url", *derpURL,
			"pubkey", base64.RawURLEncoding.EncodeToString(pub[:]),
			"target", *target, "services", services.String())
		for _, name := range services {
			slog.Info("announcing", "name", name)
		}
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
	s := grpc.NewServer(grpc.UnaryInterceptor(authInterceptor(*token)))
	proto.RegisterP2PServer(s, newServer(*bind, engine))
	slog.Info("p2p stub listening", "addr", *addr, "bind", *bind, "auth", *token != "", "derp", *derpURL != "")
	if err := s.Serve(ln); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}

// nameRe constrains service names: lowercase alphanumeric + hyphen, ≤64
// bytes. The cap is a protocol sanity bound, not a collision safeguard —
// key/name precedence in OpenTunnel makes parsing unambiguous (see the
// discovery plan's boundary notes).
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// stringList collects repeated --service values.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	if !nameRe.MatchString(v) {
		return fmt.Errorf("invalid service name %q (want [a-z0-9][a-z0-9-]{0,63})", v)
	}
	*s = append(*s, v)
	return nil
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
