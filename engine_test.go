package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"p2p/internal/derpclient"
)

// relayServer is an in-process DERP-style relay: clients (engines) connect
// over WebSocket, and every SendPacket is forwarded to its destination key
// as a RecvPacket. It exercises the engine's packet pump, mux sessions, and
// bridging without needing a real derper (real-derper interop is a separate
// e2e gate).

var (
	relayPriv derpclient.PrivateKey
	relayOnce sync.Once
)

func relayKey() derpclient.PrivateKey {
	relayOnce.Do(func() { relayPriv, _, _ = derpclient.Generate() })
	return relayPriv
}

type relayServer struct {
	srv *httptest.Server

	mu      sync.Mutex
	clients map[[32]byte]*relayClient
}

type relayClient struct {
	w  *frameW
	mu sync.Mutex
}

type frameW struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (w *frameW) write(t byte, body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var hdr [5]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if err := w.ws.Write(context.Background(), websocket.MessageBinary, hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		return w.ws.Write(context.Background(), websocket.MessageBinary, body)
	}
	return nil
}

func (s *relayServer) start(t *testing.T) string {
	t.Helper()
	s.clients = make(map[[32]byte]*relayClient)
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(hw http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(hw, r, &websocket.AcceptOptions{
			Subprotocols:    []string{"derp"},
			OriginPatterns:  []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		if ws.Subprotocol() != "derp" {
			return
		}
		s.serveClient(r.Context(), ws)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return "ws://" + s.srv.Listener.Addr().String() + "/derp"
}

func (s *relayServer) serveClient(ctx context.Context, ws *websocket.Conn) {
	skey := relayKey()
	spub := skey.Public()
	w := &frameW{ws: ws}
	// greeting: magic + server public key
	greeting := make([]byte, 0, 8+32)
	greeting = append(greeting, derpclient.Magic...)
	greeting = append(greeting, spub[:]...)
	w.write(0x01, greeting)

	conn := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	var myPub [32]byte
	registered := false
	defer func() {
		// Real derper: on disconnect broadcast PeerGone (key + 1B reason).
		if !registered {
			return
		}
		s.mu.Lock()
		delete(s.clients, myPub)
		remaining := make([]*relayClient, 0, len(s.clients))
		for _, rc := range s.clients {
			remaining = append(remaining, rc)
		}
		s.mu.Unlock()
		gone := append(append([]byte{}, myPub[:]...), 0x01)
		for _, rc := range remaining {
			rc.w.write(0x08, gone)
		}
	}()
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return
		}
		t := hdr[0]
		l := binary.BigEndian.Uint32(hdr[1:])
		body := make([]byte, l)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		switch t {
		case 0x02: // ClientInfo: box proof + register
			if len(body) < 32 {
				return
			}
			copy(myPub[:], body[:32])
			clientPub := derpclient.PublicKey(myPub)
			if _, ok := skey.OpenFrom(clientPub, body[32:]); !ok {
				return // bad box
			}
			// Register, snapshot existing peers (to announce to the new
			// client) and their channels (for the broadcast to them).
			s.mu.Lock()
			existing := make([]*relayClient, 0, len(s.clients))
			var present []byte
			for k, rc := range s.clients {
				existing = append(existing, rc)
				present = append(present, k[:]...)
			}
			s.clients[myPub] = &relayClient{w: w}
			s.mu.Unlock()
			registered = true
			// ServerInfo first: the handshake reads exactly this frame next.
			w.write(0x03, skey.SealTo(clientPub, []byte("{}")))
			// Presence mirrors the official derper: existing clients learn
			// the new peer, and the new peer learns who is already present.
			for _, rc := range existing {
				rc.w.write(0x09, myPub[:])
			}
			if len(present) > 0 {
				w.write(0x09, present)
			}
		case 0x04: // SendPacket: route by dst key
			if len(body) < 32 {
				return
			}
			var dst [32]byte
			copy(dst[:], body[:32])
			s.mu.Lock()
			rc := s.clients[dst]
			s.mu.Unlock()
			if rc == nil {
				continue // unknown destination: drop like the real server
			}
			pkt := make([]byte, 0, 32+len(body)-32)
			pkt = append(pkt, myPub[:]...)
			pkt = append(pkt, body[32:]...)
			rc.w.write(0x05, pkt)
		case 0x06: // keepalive
		case 0x12: // ping → pong
			w.write(0x13, body)
		}
	}
}

func startEcho(t *testing.T) string {
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
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}

func TestEngineRoundTripThroughRelay(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, nil, slog.Default())
	engineB := newEngine(url, echo, privB, nil, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	// Both hosts connect to the relay at startup (rendezvous registration).
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// A opens a tunnel stream to B; B accepts and bridges to the echo
	// server. A writes, the echo bounces it back through B.
	stream, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 5)
	if _, err := stream.Write([]byte("ping!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping!" {
		t.Fatalf("round trip payload = %q", buf)
	}

	// Reverse direction: B opens a stream to A. A has no --target, so the
	// inbound stream must be refused (closed) — the write succeeds locally
	// but the read side hits EOF.
	s2, err := engineB.OpenStream(engineA.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := s2.Write([]byte("x")); err != nil {
		t.Fatalf("write on refused inbound stream: %v", err)
	}
	s2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := s2.Read(buf); err == nil {
		t.Fatal("expected EOF on refused inbound stream")
	}
}

func TestParsePeerKey(t *testing.T) {
	_, pub, _ := derpclient.Generate()
	b64 := base64.RawURLEncoding.EncodeToString(pub[:])
	if _, err := parsePeerKey(b64); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	if _, err := parsePeerKey("not-a-key"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := parsePeerKey("AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}

// waitFor polls cond until it holds or d elapses.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestPresenceSurface verifies the derpclient expands PeerPresent/PeerGone
// frames into Presence() events as the relay hosts come and go.
func TestPresenceSurface(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	priv1, _, _ := derpclient.Generate()
	priv2, _, _ := derpclient.Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c1, err := derpclient.Dial(ctx, url, priv1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	// Subscribe before c2 connects: enqueuePresence drops events when no
	// consumer has created the lazy channel yet.
	ch := c1.Presence()
	go func() {
		for {
			if _, _, err := c1.Recv(); err != nil {
				return // connection closed
			}
		}
	}()

	c2, err := derpclient.Dial(ctx, url, priv2, nil)
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Present && ev.Key == c2.PublicKey() {
				goto present
			}
		case <-deadline:
			t.Fatal("no PeerPresent observed for the second client")
		}
	}
present:
	c2.Close()
	deadline = time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if !ev.Present && ev.Key == c2.PublicKey() {
				return
			}
		case <-deadline:
			t.Fatal("no PeerGone observed for the second client")
		}
	}
}

// TestServiceNameDiscovery resolves a service name to a peer and tunnels
// through it, bridging to the peer's echo target.
func TestServiceNameDiscovery(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, nil, slog.Default())
	engineB := newEngine(url, echo, privB, []string{"foo"}, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	if !waitFor(t, 5*time.Second, func() bool {
		_, ok := engineA.Lookup("foo")
		return ok
	}) {
		t.Fatal("A never resolved service name \"foo\"")
	}

	// OpenTunnel("foo") resolves the name to B and bridges to B's echo.
	srv := newServer("127.0.0.1", engineA)
	reply, err := srv.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.CloseTunnel(context.Background(), &proto.CloseTunnelRequest{Id: reply.Id})

	conn, err := net.Dial("tcp", reply.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 6)
	if _, err := conn.Write([]byte("hello!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello!" {
		t.Fatalf("tunnel round trip = %q", buf)
	}
}

// TestUnknownNameNotFound asserts an unresolvable peer string is NotFound.
func TestUnknownNameNotFound(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, nil, slog.Default())
	defer engineA.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	srv := newServer("127.0.0.1", engineA)
	if _, err := srv.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{Peer: "no-such-service"}); status.Code(err) != codes.NotFound {
		t.Fatalf("OpenTunnel unknown name: err=%v code=%v, want NotFound", err, status.Code(err))
	}
}

// TestPeerGoneEviction asserts a departing host's names are evicted from the
// cache via PeerGone, not left until TTL expiry.
func TestPeerGoneEviction(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, nil, slog.Default())
	engineB := newEngine(url, "", privB, []string{"foo"}, slog.Default())
	defer engineA.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 5*time.Second, func() bool {
		_, ok := engineA.Lookup("foo")
		return ok
	}) {
		t.Fatal("A never learned foo")
	}

	engineB.Close() // B departs; the relay broadcasts PeerGone to A.
	if !waitFor(t, 5*time.Second, func() bool {
		_, ok := engineA.Lookup("foo")
		return !ok
	}) {
		t.Fatal("foo survived PeerGone")
	}
}

// TestAnnounceInterleavesWithSession asserts control announcements share the
// packet stream with session data without corrupting the mux session.
func TestAnnounceInterleavesWithSession(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, []string{"alice"}, slog.Default())
	engineA.announcePeriod = 200 * time.Millisecond
	engineB := newEngine(url, echo, privB, nil, slog.Default())
	defer engineA.Close()
	defer engineB.Close()

	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Establish the session; A's periodic announcements (every 200ms) now
	// flow alongside session data on the same packet stream.
	stream, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 5)
	if _, err := stream.Write([]byte("ping!")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping!" {
		t.Fatalf("round trip = %q", buf)
	}

	// B must have applied A's name announcement (control frames dispatched
	// while the session stream stayed intact).
	if !waitFor(t, 5*time.Second, func() bool {
		key, ok := engineB.Lookup("alice")
		return ok && key == engineA.pub
	}) {
		t.Fatal("B never learned A's service name")
	}
}
