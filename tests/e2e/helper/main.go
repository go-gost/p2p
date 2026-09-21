// Command helper is the e2e suite's sidecar: the pieces a shell script would
// otherwise need extra tooling for. It is intentionally tiny and dependency-
// free beyond what the p2p module already pulls in (grpc + the plugin proto).
//
//	helper status <grpc-addr> [token]   query P2P/Status, print JSON
//	helper http <listen-addr>           HTTP echo server ("hello-p2p")
//	helper udp <listen-addr>            UDP echo server
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper {status|http|udp} ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "status":
		if len(os.Args) < 3 {
			die("usage: helper status <grpc-addr> [token]")
		}
		token := ""
		if len(os.Args) > 3 {
			token = os.Args[3]
		}
		if err := status(os.Args[2], token); err != nil {
			die(err.Error())
		}
	case "http":
		if len(os.Args) < 3 {
			die("usage: helper http <listen-addr>")
		}
		if err := httpEcho(os.Args[2]); err != nil {
			die(err.Error())
		}
	case "udp":
		if len(os.Args) < 3 {
			die("usage: helper udp <listen-addr>")
		}
		if err := udpEcho(os.Args[2]); err != nil {
			die(err.Error())
		}
	default:
		die("unknown subcommand " + os.Args[1])
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// status prints the StatusReply as one-line JSON so a shell assertion can grep
// fields without a JSON parser.
func status(addr, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "token", token)
	}
	reply, err := proto.NewP2PClient(conn).Status(ctx, &proto.StatusRequest{})
	if err != nil {
		return err
	}
	out := map[string]int64{
		"tunnels":        int64(reply.GetTunnels()),
		"direct_peers":   int64(reply.GetDirectPeers()),
		"derp_peers":     int64(reply.GetDerpPeers()),
		"punch_attempts": reply.GetPunchAttempts(),
		"punch_success":  reply.GetPunchSuccess(),
		"streams_direct": reply.GetStreamsDirect(),
		"streams_derp":   reply.GetStreamsDerp(),
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
	return nil
}

// httpEcho serves "hello-p2p" on every path, and a 1 MiB burst on /bulk so a
// test can prove the data plane carries more than a header round-trip.
func httpEcho(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bulk" {
			w.Header().Set("Content-Type", "application/octet-stream")
			buf := make([]byte, 64*1024)
			for i := range buf {
				buf[i] = byte('a' + i%26)
			}
			for i := 0; i < 16; i++ { // 1 MiB
				if _, err := w.Write(buf); err != nil {
					return
				}
			}
			return
		}
		io.WriteString(w, "hello-p2p\n")
	})
	return http.ListenAndServe(addr, mux)
}

func udpEcho(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()
	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		if _, err := pc.WriteTo(buf[:n], src); err != nil {
			return err
		}
	}
}
