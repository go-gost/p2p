// P2P stub host: grpc control plane + TCP bridge data plane.
//
// The GOST side calls OpenTunnel(peer) over gRPC; the stub responds with a
// local TCP endpoint that bridges to the peer address. This milestone only
// proves the plugin seam — no NAT traversal, rendezvous, or encryption.
package main

import (
	"flag"
	"log/slog"
	"net"
	"os"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8003", "gRPC listen address (control plane)")
	bind := flag.String("bind", "127.0.0.1", "data plane listen IP; each tunnel gets an ephemeral port on it")
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

	s := grpc.NewServer()
	proto.RegisterP2PServer(s, newServer(*bind))
	slog.Info("p2p stub listening", "addr", *addr, "bind", *bind)
	if err := s.Serve(ln); err != nil {
		slog.Error("serve", "error", err)
		os.Exit(1)
	}
}