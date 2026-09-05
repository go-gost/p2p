// P2P stub host: grpc control plane + TCP bridge data plane.
//
// The GOST side calls OpenTunnel(peer) over gRPC; the stub responds with a
// local TCP endpoint that bridges to the peer address. This milestone only
// proves the plugin seam — no NAT traversal, rendezvous, or encryption.
package main

import (
	"context"
	"crypto/subtle"
	"flag"
	"log/slog"
	"net"
	"os"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "gRPC listen address (control plane)")
	bind := flag.String("bind", "127.0.0.1", "data plane listen IP; each tunnel gets an ephemeral port on it")
	token := flag.String("token", "", "control-plane auth token; empty disables checking (loopback default)")
	debug := flag.Bool("debug", false, "debug logging")
	flag.Parse()

	if *debug {
		slog.SetLogLoggerLevel(slog.LevelDebug)
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
	proto.RegisterP2PServer(s, newServer(*bind))
	slog.Info("p2p stub listening", "addr", *addr, "bind", *bind, "auth", *token != "")
	if err := s.Serve(ln); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
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