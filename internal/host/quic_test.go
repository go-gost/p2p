package host

import (
	"context"
	"errors"
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
	return newQUICPairTestPairWithConfig(t, clientOnStream, serverOnStream, newQUICPairTestConfig(t))
}

// newQUICPairTestPairWithConfig is newQUICPairTestPair with a caller-supplied
// config, so tests can observe what the pair does to it.
func newQUICPairTestPairWithConfig(t *testing.T, clientOnStream, serverOnStream func(net.Conn), qcfg *quic.Config) (*quicPair, *quicPair) {
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

	// The server listener must be closed once the single connection has been
	// accepted. Otherwise a second handshake could create a connection that
	// the zero-length CID cannot tell apart from the established one. Accepted
	// connections are unaffected.
	server.mu.Lock()
	ln := server.ln
	server.mu.Unlock()
	if ln == nil {
		t.Fatal("server listener is nil after establish")
	}
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer acceptCancel()
	if _, err := ln.Accept(acceptCtx); !errors.Is(err, quic.ErrServerClosed) {
		t.Fatalf("server listener Accept after establish = %v, want ErrServerClosed", err)
	}

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
			select {
			case <-server.acceptDone:
				t.Fatal("server acceptStreams exited before close")
			default:
			}
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

	// MTUs above quic-go's packet buffer maximum must be clamped instead of
	// left for validateConfig to mutate during the handshake.
	s.MTU = 9000
	cfg = quicConfigFromSettings(s)
	if got := int(cfg.InitialPacketSize); got != quicMaxInitialPacketSize {
		t.Fatalf("InitialPacketSize for MTU %d = %d, want %d", s.MTU, got, quicMaxInitialPacketSize)
	}
}

// TestQUICPairClonesConfig proves the pair (and quic-go) mutate a private copy
// of the caller's config: sharing one config between pairs must not race or
// leak quic-go's clamp back to the caller.
func TestQUICPairClonesConfig(t *testing.T) {
	qcfg := newQUICPairTestConfig(t)
	qcfg.InitialPacketSize = 1500

	newQUICPairTestPairWithConfig(t, nil, nil, qcfg)
	if qcfg.InitialPacketSize != 1500 {
		t.Fatalf("caller config InitialPacketSize = %d after establish, want 1500", qcfg.InitialPacketSize)
	}
}

// TestQUICPairEstablishRetry proves a failed handshake leaves the relay
// underlay and pair lifetime usable, so establish can be retried without a new
// multiPathConn.
func TestQUICPairEstablishRetry(t *testing.T) {
	clientID, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	serverID, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongID, err := newQUICIdentity()
	if err != nil {
		t.Fatal(err)
	}

	handled := make(chan error, 1)
	serverOnStream := func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, len("hello"))
		if _, err := io.ReadFull(c, buf); err != nil {
			handled <- err
			return
		}
		_, err := c.Write([]byte("world"))
		handled <- err
	}

	clientPC, serverPC := newPacketPipe()
	qcfg := newQUICPairTestConfig(t)
	client := newQUICPair(&engine{}, derpclient.PublicKey{1}, quicRoleClient,
		quicTLSConfig(clientID, wrongID.fp, false), qcfg, nil)
	server := newQUICPair(&engine{}, derpclient.PublicKey{2}, quicRoleServer,
		quicTLSConfig(serverID, clientID.fp, true), qcfg, serverOnStream)
	t.Cleanup(func() {
		client.close()
		server.close()
	})
	if err := client.addRelayUnderlay(clientPC); err != nil {
		t.Fatal(err)
	}
	if err := server.addRelayUnderlay(serverPC); err != nil {
		t.Fatal(err)
	}

	// First attempt: the client pins the wrong fingerprint, so the handshake
	// fails. The server is still parked in Accept, so cancel its context once
	// the client reports the failure instead of waiting for a timeout.
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.establish(serverCtx) }()

	clientCtx, cancelClient := context.WithTimeout(context.Background(), 5*time.Second)
	err = client.establish(clientCtx)
	cancelClient()
	stopServer()
	if err == nil {
		t.Fatal("client establish with wrong pin succeeded, want failure")
	}
	select {
	case err := <-serverErr:
		if err == nil {
			t.Fatal("server establish succeeded after client handshake failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server establish did not return after context cancellation")
	}

	client.mu.Lock()
	tr, conn, closed := client.tr, client.conn, client.closed
	client.mu.Unlock()
	if closed {
		t.Fatal("client pair closed after establish failure, want retryable")
	}
	if tr != nil {
		t.Fatal("client transport not reset after establish failure")
	}
	if conn != nil {
		t.Fatal("client conn set after establish failure")
	}
	select {
	case <-client.mp.closed:
		t.Fatal("client multiPathConn closed after establish failure")
	default:
	}
	if _, err := clientPC.WriteTo([]byte("probe"), clientPC.LocalAddr()); err != nil {
		t.Fatalf("relay underlay unusable after establish failure: %v", err)
	}

	// Retry on the same pairs and the same relay underlay, now with the
	// correct pin.
	client.tlsCfg = quicTLSConfig(clientID, serverID.fp, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverErr = make(chan error, 1)
	go func() { serverErr <- server.establish(ctx) }()
	if err := client.establish(ctx); err != nil {
		t.Fatalf("retry client establish: %v", err)
	}
	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("retry server establish: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("retry server establish timed out")
	}

	c, err := client.openStream(ctx)
	if err != nil {
		t.Fatalf("openStream after retry: %v", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("write after retry: %v", err)
	}
	buf := make([]byte, len("world"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read after retry: %v", err)
	}
	if got := string(buf); got != "world" {
		t.Fatalf("read after retry = %q, want world", got)
	}
	select {
	case err := <-handled:
		if err != nil {
			t.Fatalf("server handler after retry: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not handle the stream after retry")
	}
}

// TestQUICStreamConnCloseBothDirections proves Close resets the receive side
// too: a peer blocked on writing cannot keep feeding a stream nobody reads.
func TestQUICStreamConnCloseBothDirections(t *testing.T) {
	peerStream := make(chan net.Conn, 1)
	startWrite := make(chan struct{})
	peerWriteErr := make(chan error, 1)
	serverOnStream := func(c net.Conn) {
		defer c.Close()
		// A QUIC stream only becomes visible to the peer once it carries data,
		// so the client primes it before this handler can observe it.
		hello := make([]byte, 2)
		if _, err := io.ReadFull(c, hello); err != nil {
			peerWriteErr <- fmt.Errorf("server read: %w", err)
			return
		}
		peerStream <- c
		<-startWrite
		buf := make([]byte, 32<<10)
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		var err error
		for i := 0; i < 4096; i++ {
			if _, err = c.Write(buf); err != nil {
				break
			}
		}
		if err == nil {
			err = errors.New("peer writes kept succeeding after remote Close")
		}
		peerWriteErr <- err
	}

	client, _ := newQUICPairTestPair(t, nil, serverOnStream)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.openStream(ctx)
	if err != nil {
		t.Fatalf("openStream: %v", err)
	}
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatalf("prime stream: %v", err)
	}
	select {
	case <-peerStream:
	case <-ctx.Done():
		t.Fatal("server did not accept the stream")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(startWrite)

	select {
	case err := <-peerWriteErr:
		if err == nil {
			t.Fatal("peer write succeeded after Close")
		}
	case <-ctx.Done():
		t.Fatal("peer write did not unblock after Close")
	}
}

// TestQUICPairOpenStreamState covers the two states openStream must reject
// before a connection exists and after the pair is closed.
func TestQUICPairOpenStreamState(t *testing.T) {
	p := newQUICPair(&engine{}, derpclient.PublicKey{1}, quicRoleClient, nil, nil, nil)
	if _, err := p.openStream(context.Background()); !errors.Is(err, errQUICPairNoConn) {
		t.Fatalf("openStream before establish = %v, want %v", err, errQUICPairNoConn)
	}
	p.close()
	if _, err := p.openStream(context.Background()); !errors.Is(err, errQUICPairClosed) {
		t.Fatalf("openStream after close = %v, want %v", err, errQUICPairClosed)
	}
}
