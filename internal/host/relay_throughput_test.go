package host

import (
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// relayTPMiBEnv switches on TestRelayDataPathThroughput. The test pushes real
// megabytes through the relay to price the data path, which is far too slow for
// the normal gate, so it only runs when asked for.
const relayTPMiBEnv = "P2P_RELAY_TP_MIB"

// startDiscard returns a TCP address that accepts and drains whatever arrives,
// so a throughput run measures the relay path rather than an echo target.
func startDiscard(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().String()
}

// TestRelayDataPathThroughput prices the relay data path: it measures how many
// bits per second the tunnel actually delivers between two engines, which is the
// number field performance work has to move. Run it with -cpuprofile to see
// where the per-byte cost goes:
//
//	P2P_RELAY_TP_MIB=256 go test -run TestRelayDataPathThroughput \
//	  -cpuprofile cpu.out ./internal/host/
//	go tool pprof -top cpu.out
func TestRelayDataPathThroughput(t *testing.T) {
	mib := 0
	if v := os.Getenv(relayTPMiBEnv); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("%s=%q: %v", relayTPMiBEnv, v, err)
		}
		mib = n
	}
	if mib <= 0 {
		t.Skipf("set %s=<MiB> to measure the relay data path", relayTPMiBEnv)
	}
	total := int64(mib) << 20

	rs := &relayServer{}
	url := rs.start(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.New(slog.NewTextHandler(io.Discard, nil)))
	eB := newEngine(url, startDiscard(t), privB, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 32<<10)
	start := time.Now()
	for sent := int64(0); sent < total; {
		n, err := conn.Write(buf)
		if err != nil {
			t.Fatalf("wrote %d of %d bytes: %v", sent, total, err)
		}
		sent += int64(n)
	}
	elapsed := time.Since(start)
	mbit := float64(total) * 8 / 1e6
	t.Logf("relay data path: %d MiB in %s = %.1f Mbit/s (%.1f MiB/s)",
		mib, elapsed.Round(time.Millisecond), mbit/elapsed.Seconds(),
		float64(total)/(1<<20)/elapsed.Seconds())
}
