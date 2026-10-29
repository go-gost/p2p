package host

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/quic-go/quic-go"
)

// newQUICPairTestConfig returns the QUIC config resolved from the package
// defaults, so the test exercises the same mapping the engine uses.
func newQUICPairTestConfig(t *testing.T) *quic.Config {
	t.Helper()
	s, err := resolveQUICSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	return quicConfigFromSettings(s)
}

// newQUICPairTestPair builds a client and a server pair over one in-memory
// relay pipe, with real TLS handshakes and the two identities pinned to each
// other. It returns once both sides are established.
func newQUICPairTestPair(t *testing.T, clientOnStream, serverOnStream func(net.Conn)) (*quicPair, *quicPair) {
	t.Helper()

	clientID, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	clientPC, serverPC := newPacketPipe()
	qcfg := newQUICPairTestConfig(t)

	client := newQUICPair(&engine{}, derpclient.PublicKey{1}, quicRoleClient,
		quicTLSConfig(clientID, serverID.fp, false), qcfg, clientOnStream)
	server := newQUICPair(&engine{}, derpclient.PublicKey{2}, quicRoleServer,
		quicTLSConfig(serverID, clientID.fp, true), qcfg, serverOnStream)
	t.Cleanup(func() {
		client.close()
		server.close()
	})

	if err := client.addRelayUnderlay(clientPC); err != nil {
		t.Fatalf("client addRelayUnderlay: %v", err)
	}
	if err := server.addRelayUnderlay(serverPC); err != nil {
		t.Fatalf("server addRelayUnderlay: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The server blocks in Accept, so it must listen while the client dials.
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.establish(ctx) }()
	if err := client.establish(ctx); err != nil {
		t.Fatalf("client establish: %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server establish: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("server establish timed out")
	}
	return client, server
}

func TestQUICPairRelayEcho(t *testing.T) {
	handled := make(chan error, 1)
	serverOnStream := func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, len("hello"))
		if _, err := io.ReadFull(c, buf); err != nil {
			handled <- fmt.Errorf("server read: %w", err)
			return
		}
		if got := string(buf); got != "hello" {
			handled <- fmt.Errorf("server read %q, want hello", got)
			return
		}
		if _, err := c.Write([]byte("world")); err != nil {
			handled <- fmt.Errorf("server write: %w", err)
			return
		}
		handled <- nil
	}

	client, server := newQUICPairTestPair(t, nil, serverOnStream)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.openStream(ctx)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	defer c.Close()
	sc, ok := c.(*quicStreamConn)
	if !ok {
		t.Fatalf("openStream returned %T, want *quicStreamConn", c)
	}
	if got := sc.RemoteAddr(); got == nil || got.String() != quicPathRelay {
		t.Fatalf("stream remote addr = %v, want %q", got, quicPathRelay)
	}
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, len("world"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("client read: %v", err)
	}
	if got := string(buf); got != "world" {
		t.Fatalf("client read %q, want world", got)
	}
	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not handle the stream")
	}

	if got := client.pathName(); got != quicPathRelay {
		t.Fatalf("client path = %q, want relay", got)
	}
	if got := server.pathName(); got != quicPathRelay {
		t.Fatalf("server path = %q, want relay", got)
	}
	client.mu.Lock()
	conn := client.conn
	client.mu.Unlock()
	if conn == nil {
		t.Fatal("client conn is nil after establish")
	}
	state := conn.ConnectionState()
	if state.Used0RTT {
		t.Fatal("connection used 0-RTT")
	}
	if got := state.TLS.NegotiatedProtocol; got != quicALPN {
		t.Fatalf("ALPN = %q, want %q", got, quicALPN)
	}
}

func TestQUICPairCloseUnblocksAccept(t *testing.T) {
	for _, tc := range []struct {
		name  string
		close func(client, server *quicPair)
	}{
		{"client", func(client, _ *quicPair) { client.close() }},
		{"server", func(_, server *quicPair) { server.close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := newQUICPairTestPair(t, nil, nil)
			tc.close(client, server)

			select {
			case <-server.acceptDone:
			case <-time.After(5 * time.Second):
				t.Fatal("server acceptStreams did not exit after close")
			}

			server.mu.Lock()
			conn := server.conn
			server.mu.Unlock()
			if conn == nil {
				t.Fatal("server conn is nil after establish")
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("server QUIC connection did not close")
			}
		})
	}
}

func TestQUICConfigFromSettings(t *testing.T) {
	s := quicSettings{
		MTU:              1400,
		KeepAlive:        3 * time.Second,
		Idle:             20 * time.Second,
		HandshakeTimeout: 7 * time.Second,
	}
	cfg := quicConfigFromSettings(s)
	if cfg.HandshakeIdleTimeout != s.HandshakeTimeout {
		t.Fatalf("HandshakeIdleTimeout = %v, want %v", cfg.HandshakeIdleTimeout, s.HandshakeTimeout)
	}
	if cfg.MaxIdleTimeout != s.Idle {
		t.Fatalf("MaxIdleTimeout = %v, want %v", cfg.MaxIdleTimeout, s.Idle)
	}
	if cfg.KeepAlivePeriod != s.KeepAlive {
		t.Fatalf("KeepAlivePeriod = %v, want %v", cfg.KeepAlivePeriod, s.KeepAlive)
	}
	if int(cfg.InitialPacketSize) != s.MTU {
		t.Fatalf("InitialPacketSize = %d, want %d", cfg.InitialPacketSize, s.MTU)
	}
	if !cfg.DisablePathMTUDiscovery {
		t.Fatal("DisablePathMTUDiscovery = false, want true")
	}
	if cfg.MaxIncomingStreams != quicMaxIncomingStreams {
		t.Fatalf("MaxIncomingStreams = %d, want %d", cfg.MaxIncomingStreams, quicMaxIncomingStreams)
	}
	if cfg.MaxIncomingUniStreams != quicMaxIncomingUniStreams {
		t.Fatalf("MaxIncomingUniStreams = %d, want %d", cfg.MaxIncomingUniStreams, quicMaxIncomingUniStreams)
	}
	if cfg.Allow0RTT {
		t.Fatal("Allow0RTT = true, want false")
	}
}
