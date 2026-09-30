package host

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/go-gost/p2p/internal/derpclient"
	"github.com/xtaci/smux"
)

// newTestSess returns a live smux session over an in-memory pipe, for tests
// that only need a session whose IsClosed() can be flipped.
func newTestSess(t *testing.T) *smux.Session {
	t.Helper()
	c1, c2 := net.Pipe()
	sess, err := smux.Client(c1, smux.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		sess.Close()
		c2.Close()
	})
	return sess
}

// TestDirectLiveNoSideEffect pins the one trap in the transport-stats feature:
// the gauge probe must report a dead session without the teardown and re-punch
// that session() performs, or a Status query would churn connections. If live()
// ever delegates to session(), the state assertion below fails.
func TestDirectLiveNoSideEffect(t *testing.T) {
	sess := newTestSess(t)
	dc := &directConn{peer: derpclient.PublicKey{1}, sess: sess, state: directUp}

	if !dc.live() {
		t.Fatal("live() = false for an open session, want true")
	}

	sess.Close()

	if dc.live() {
		t.Fatal("live() = true for a closed session, want false")
	}
	dc.mu.Lock()
	state := dc.state
	dc.mu.Unlock()
	if state != directUp {
		t.Fatalf("live() mutated state to %v, want directUp (side-effect free)", state)
	}
}

// TestTransportCounts covers the gauge classification: a peer with a live
// direct session counts as direct and must not also be counted as derp; peers
// on the relay alone count as derp.
func TestTransportCounts(t *testing.T) {
	e := &engine{
		direct:   true,
		stunAddr: "127.0.0.1:3478",
		directs:  make(map[derpclient.PublicKey]*directConn),
		peers:    make(map[derpclient.PublicKey]*peerConn),
	}

	peerDirect := derpclient.PublicKey{1}
	peerRelay := derpclient.PublicKey{2}

	dc := &directConn{e: e, peer: peerDirect, sess: newTestSess(t), state: directUp}
	e.directs[peerDirect] = dc
	e.peers[peerDirect] = &peerConn{}
	e.peers[peerRelay] = &peerConn{}

	direct, derp := e.transportCounts()
	if direct != 1 {
		t.Fatalf("direct = %d, want 1", direct)
	}
	if derp != 1 {
		t.Fatalf("derp = %d, want 1 (the direct peer must not double-count)", derp)
	}

	// The same classification is available per peer, which is what a caller
	// listing peers uses.
	transports := e.peerTransports()
	if len(transports) != 2 {
		t.Fatalf("peerTransports = %v, want both peers", transports)
	}
	if got := transports[keyName(peerDirect)]; got != "direct" {
		t.Errorf("peer %s transport = %q, want direct", keyName(peerDirect), got)
	}
	if got := transports[keyName(peerRelay)]; got != "derp" {
		t.Errorf("peer %s transport = %q, want derp", keyName(peerRelay), got)
	}

	// Losing the direct session moves that peer into the relay column.
	dc.mu.Lock()
	sess := dc.sess
	dc.mu.Unlock()
	sess.Close()

	direct, derp = e.transportCounts()
	if direct != 0 || derp != 2 {
		t.Fatalf("after session death: direct = %d, derp = %d, want 0, 2", direct, derp)
	}
	if got := e.peerTransports()[keyName(peerDirect)]; got != "derp" {
		t.Errorf("after session death: peer transport = %q, want derp", got)
	}
}

// TestPeerTransportReasons: a relayed peer reports the most specific reason
// available — its own punch state first, then the host-wide one — which is what
// a caller turns into an icon and a tooltip. Being able to tell "STUN does not
// answer" from "punching cannot work here at all" is the point.
func TestPeerTransportReasons(t *testing.T) {
	newEngine := func() *engine {
		return &engine{
			direct:   true,
			stunAddr: "127.0.0.1:3478",
			directs:  make(map[derpclient.PublicKey]*directConn),
			peers:    make(map[derpclient.PublicKey]*peerConn),
		}
	}
	peer := derpclient.PublicKey{3}

	cases := []struct {
		name string
		mut  func(e *engine)
		want string
	}{
		{"punch in flight", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directAttempting}
		}, transportPunching},
		{"punch failed", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directBackoff, failed: true}
		}, transportFailed},
		{"failed, retry in flight", func(e *engine) {
			e.directs[peer] = &directConn{e: e, peer: peer, state: directAttempting, failed: true}
		}, transportFailed},
		{"direct switched off", func(e *engine) {
			e.direct = false
			e.directs[peer] = &directConn{e: e, peer: peer}
		}, transportDisabled},
		{"no STUN, no IPv6", func(e *engine) { e.stunAddr = "" }, transportNoCandidates},
		{"STUN silent", func(e *engine) { e.stunFailed.Store(true) }, transportStunUnreachable},
		{"STUN silent but IPv6 exists", func(e *engine) {
			e.stunFailed.Store(true)
			e.v6Available = true
		}, transportRelay},
		{"plain relay", func(e *engine) {}, transportRelay},
	}
	for _, tc := range cases {
		e := newEngine()
		e.peers[peer] = &peerConn{}
		tc.mut(e)
		if got := e.peerTransports()[keyName(peer)]; got != tc.want {
			t.Errorf("%s: transport = %q, want %q", tc.name, got, tc.want)
		}
	}

	// A live punch wins over every reason.
	e := newEngine()
	e.peers[peer] = &peerConn{}
	e.stunFailed.Store(true)
	e.directs[peer] = &directConn{e: e, peer: peer, sess: newTestSess(t), state: directUp}
	if got := e.peerTransports()[keyName(peer)]; got != transportDirect {
		t.Errorf("live session: transport = %q, want direct", got)
	}

	// A host-wide cause outranks a peer's own failed round: with STUN silent
	// and no IPv6, that is the thing to fix, not the symptom.
	e = newEngine()
	e.peers[peer] = &peerConn{}
	e.stunFailed.Store(true)
	e.directs[peer] = &directConn{e: e, peer: peer, state: directBackoff, failed: true}
	if got := e.peerTransports()[keyName(peer)]; got != transportStunUnreachable {
		t.Errorf("stun silent + failed round: transport = %q, want %q", got, transportStunUnreachable)
	}
}

// TestTransportStatsCounters drives a real punch and checks the counters the
// status reply reads.
func TestTransportStatsCounters(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	stun := startFakeSTUN(t, "")
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	engineA.stunAddr, engineB.stunAddr = stun, stun
	defer engineA.Close()
	defer engineB.Close()

	engineA.Connect()
	engineB.Connect()

	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "stats")
	s.Close()

	waitFor(t, 5*time.Second, func() bool { return hasDirect(engineA, pubB) })

	punchAttempts, punchSuccess, streamsDirect, _ := engineA.stats.snapshot()
	if punchAttempts < 1 {
		t.Fatalf("punchAttempts = %d, want >= 1", punchAttempts)
	}
	if punchSuccess < 1 {
		t.Fatalf("punchSuccess = %d, want >= 1", punchSuccess)
	}
	if streamsDirect < 1 {
		t.Fatalf("streamsDirect = %d, want >= 1", streamsDirect)
	}
}

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

	mu       sync.Mutex
	clients  map[[32]byte]*relayClient
	dropData bool // when true, drop 0x01 data frames (control still flows)
	dropPong bool // when true, stop answering pings (a half-open relay path)
	// dropCtrl, when set, is consulted for every forwarded control frame; true
	// drops it, so a test can lose one handshake half and prove the retry heals.
	dropCtrl func(dst [32]byte, payload []byte) bool
}

func (s *relayServer) setDropData(v bool) {
	s.mu.Lock()
	s.dropData = v
	s.mu.Unlock()
}

func (s *relayServer) setDropPong(v bool) {
	s.mu.Lock()
	s.dropPong = v
	s.mu.Unlock()
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
	var registered bool
	defer func() {
		if !registered {
			return
		}
		// A disconnecting peer is reported gone to everyone else, like the real
		// derper (PeerGoneReasonDisconnected).
		s.mu.Lock()
		delete(s.clients, myPub)
		others := make([]*frameW, 0, len(s.clients))
		for _, c := range s.clients {
			others = append(others, c.w)
		}
		s.mu.Unlock()
		gone := append([]byte{}, myPub[:]...)
		gone = append(gone, 0x00)
		for _, oc := range others {
			oc.write(0x08, gone)
		}
	}()
	notified := map[[32]byte]bool{} // like the real derper: PeerGone once per dst
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
			s.mu.Lock()
			s.clients[myPub] = &relayClient{w: w}
			s.mu.Unlock()
			registered = true
			// ServerInfo: sealed by the server to the client.
			w.write(0x03, skey.SealTo(clientPub, []byte("{}")))
		case 0x04: // SendPacket: route by dst key
			if len(body) < 32 {
				return
			}
			var dst [32]byte
			copy(dst[:], body[:32])
			payload := body[32:]
			s.mu.Lock()
			rc := s.clients[dst]
			drop := s.dropData && len(payload) > 0 && payload[0] == 0x01
			dropCtrl := s.dropCtrl
			s.mu.Unlock()
			if rc == nil {
				// Unknown destination: tell the sender the peer is gone once,
				// like the real derper (PeerGoneReasonNotHere).
				if !notified[dst] {
					notified[dst] = true
					gone := append([]byte{}, dst[:]...)
					gone = append(gone, 0x01)
					w.write(0x08, gone)
				}
				continue
			}
			if drop {
				continue // drop data frames, keep control frames flowing
			}
			if dropCtrl != nil && len(payload) > 0 && payload[0] == 0x00 && dropCtrl(dst, payload) {
				continue // a test deliberately lost this control frame
			}
			pkt := make([]byte, 0, 32+len(payload))
			pkt = append(pkt, myPub[:]...)
			pkt = append(pkt, payload...)
			rc.w.write(0x05, pkt)
		case 0x06: // keepalive
		case 0x12: // ping → pong
			s.mu.Lock()
			drop := s.dropPong
			s.mu.Unlock()
			if drop {
				continue // a path that carries our bytes but never answers
			}
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
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
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

// TestConnectErrorKeepsDialCause: a failed dial must surface its cause. A bare
// "connect failed" hides TLS/DNS problems the caller can act on (a self-signed
// relay, a bad CA file, a typo in the URL), which the log line alone does not
// fix for an API caller.
func TestConnectErrorKeepsDialCause(t *testing.T) {
	priv, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine("wss://127.0.0.1:1/derp", "", priv, slog.Default())
	defer e.Close()

	err = e.Connect()
	if err == nil {
		t.Fatal("Connect to a refused relay = nil error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("Connect error = %v, want the dial cause (connection refused)", err)
	}
}

// TestRelaySilent: the watchdog's verdict, which is about a ping going
// unanswered — not about frames arriving, since a quiet relay carries none
// either way. It must not judge before the first probe, must tolerate a round
// trip that is merely in flight, and must fire once the outstanding probe is
// older than the ceiling.
func TestRelaySilent(t *testing.T) {
	now := time.Now()

	if relaySilent(time.Time{}, time.Time{}, now) {
		t.Error("no verdict before the first probe")
	}
	if relaySilent(now.Add(-relayDeadPeriod/4), time.Time{}, now) {
		t.Error("a fresh unanswered ping is not silence")
	}
	if relaySilent(now.Add(-relayDeadPeriod), time.Time{}, now) {
		t.Error("exactly at the ceiling is not yet silence")
	}
	if !relaySilent(now.Add(-relayDeadPeriod-time.Second), time.Time{}, now) {
		t.Error("an unanswered ping older than the ceiling is silence")
	}

	// An answered probe is never silence, however quiet the connection is: the
	// pong is newer than the ping that asked for it.
	if relaySilent(now.Add(-2*relayDeadPeriod), now.Add(-relayDeadPeriod/4), now) {
		t.Error("a fresh pong is not silence, however old the ping")
	}
	// A pong older than the ceiling, with a ping older still, is silence.
	if !relaySilent(now.Add(-2*relayDeadPeriod), now.Add(-relayDeadPeriod-time.Second), now) {
		t.Error("a pong older than the ceiling is silence")
	}
}

// TestRelaySilenceIsReconnected: a relay path can stop answering without the
// WebSocket noticing — writes sink into the kernel buffer, no frame arrives and
// nothing errors (measured on a phone switching Wi-Fi/cellular). Candidate
// exchange rides the relay, so a connection that is never torn down and redialed
// leaves every punch failing at "no peer candidates", forever. The keepalive's
// ping probe is the only thing that can see a path like that.
func TestRelaySilenceIsReconnected(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	priv, _, _ := derpclient.Generate()
	e := newEngine(url, "", priv, slog.Default())
	defer e.Close()
	if err := e.Connect(); err != nil {
		t.Fatal(err)
	}

	// An answering relay is never torn down, however short the tick.
	time.Sleep(200 * time.Millisecond)
	if !e.relayConnected() {
		t.Fatal("an answering relay was torn down")
	}

	// Stop answering pings. The connection must be declared dead (the redial is
	// the reconnect loop's business, and it does not run within this window).
	rs.setDropPong(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !e.relayConnected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("a relay that stopped answering pings was never torn down")
}

// relayState must report the engine's own relay connection: the three states a
// status consumer has to tell apart.
func TestRelayState(t *testing.T) {
	// Never dialed.
	e := &engine{}
	if up, msg := e.relayState(); up || msg != "" {
		t.Errorf("fresh engine: up=%v msg=%q, want false/\"\"", up, msg)
	}

	// Connected.
	e.client = &derpclient.Client{}
	if up, msg := e.relayState(); !up || msg != "" {
		t.Errorf("connected: up=%v msg=%q, want true/\"\"", up, msg)
	}

	// Down, with the reason a user can act on.
	e.client = nil
	e.dialErr = errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
	up, msg := e.relayState()
	if up {
		t.Error("up = true with no client")
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("msg = %q, want the dial failure", msg)
	}
}

// newEncryptedPair starts two engines on one in-process relay with the echo
// target, connected and ready.
func newEncryptedPair(t *testing.T) (*engine, *engine, *relayServer) {
	t.Helper()
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}
	return eA, eB, rs
}

// peerSecureForTest reports whether this engine's session to peer is encrypted.
func (e *engine) peerSecureForTest(peer derpclient.PublicKey) bool {
	e.mu.Lock()
	pc := e.peers[peer]
	e.mu.Unlock()
	if pc == nil {
		return false
	}
	_, _, ok := pc.secure.keys()
	return ok
}

// TestRelaySessionEncrypted drives a stream through the relay and checks that
// both ends settled an encrypted relay session (the handshake ran, not just the
// round trip).
func TestRelaySessionEncrypted(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.peerSecureForTest(eB.pub) {
		t.Fatal("A's session did not settle encrypted")
	}
	if !eB.peerSecureForTest(eA.pub) {
		t.Fatal("B's session did not settle encrypted")
	}
}

// TestRelayLinkLossRekeys: a lost relay link must drop the pair's relay security
// session, so the reconnect re-handshakes instead of reusing counters a record
// lost mid-drop advanced (sendCtr can be one ahead of the peer's recvCtr, with no
// way to realign). Both ends must settle encrypted again and traffic must flow.
// No STUN is configured, so this is relay-only and the direct path is off.
func TestRelayLinkLossRekeys(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)

	privA, _, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	engineA := newEngine(url, "", privA, slog.Default())
	engineB := newEngine(url, echo, privB, slog.Default())
	defer engineA.Close()
	defer engineB.Close()
	if err := engineA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := engineB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Carry traffic over the relay and confirm the session is encrypted.
	s, err := engineA.OpenStream(engineB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	roundTrip(t, s, "before")
	s.Close()
	if !engineA.peerSecureForTest(pubB) || !engineB.peerSecureForTest(engineA.pub) {
		t.Fatal("relay session not encrypted before the loss")
	}

	// The relay link drops. teardown kills A's adapters; it must also drop the
	// pair's relay security session or the reconnect would reuse a counter the
	// lost record advanced and never realign.
	engineA.mu.Lock()
	c := engineA.client
	engineA.mu.Unlock()
	if c == nil {
		t.Fatal("A has no relay connection")
	}
	engineA.teardown(c, errors.New("test: relay link lost"))
	engineA.mu.Lock()
	_, cached := engineA.secure[secureKey{peer: pubB, transport: secureTransportRelay}]
	engineA.mu.Unlock()
	if cached {
		t.Fatal("teardown left the peer's relay security session cached")
	}

	// A redials on the next open. Both ends must re-handshake and settle
	// encrypted, and traffic must flow again (no permanent wedge).
	waitFor(t, 10*time.Second, func() bool {
		conn, err := engineA.OpenStream(engineB.PublicKey())
		if err != nil {
			return false
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("after")); err != nil {
			return false
		}
		buf := make([]byte, len("after"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return false
		}
		return string(buf) == "after"
	})
	if !engineA.peerSecureForTest(pubB) {
		t.Fatal("A's relay session did not settle encrypted after reconnect")
	}
	if !engineB.peerSecureForTest(engineA.pub) {
		t.Fatal("B's relay session did not settle encrypted after reconnect")
	}
}

// TestRelayHandshakeLostReplyHeals: a dropped reply must not strand one side in
// plaintext. A sends its half (want set), B settles and replies, the reply is
// lost, and A's retry — still asking — makes B answer again. Without the want
// bit A would stay unsettled (and plaintext) while B encrypts, killing both mux
// sessions and churning the shared relay.
func TestRelayHandshakeLostReplyHeals(t *testing.T) {
	defer func(d time.Duration) { resendInterval = d }(resendInterval)
	resendInterval = 50 * time.Millisecond

	rs := &relayServer{}
	url := rs.start(t)
	echo := startEcho(t)
	privA, _, _ := derpclient.Generate()
	privB, _, _ := derpclient.Generate()
	eA := newEngine(url, "", privA, slog.Default())
	eB := newEngine(url, echo, privB, slog.Default())
	t.Cleanup(func() { eA.Close(); eB.Close() })
	if err := eA.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := eB.Connect(); err != nil {
		t.Fatal(err)
	}

	// Drop the first ctrlSecure frame the relay routes to A (B's first reply);
	// seen counts every such reply, so a retry reply proves A's want bit worked.
	var seen, dropped atomic.Int32
	rs.mu.Lock()
	rs.dropCtrl = func(dst [32]byte, payload []byte) bool {
		if dst != [32]byte(eA.pub) || len(payload) < 2 || payload[1] != ctrlSecure {
			return false
		}
		if seen.Add(1) == 1 {
			dropped.Add(1)
			return true
		}
		return false
	}
	rs.mu.Unlock()

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("round trip: got %q", buf)
	}
	if !eA.peerSecureForTest(eB.pub) {
		t.Fatal("A did not settle encrypted after a lost reply")
	}
	if !eB.peerSecureForTest(eA.pub) {
		t.Fatal("B did not settle encrypted")
	}
	if n := dropped.Load(); n != 1 {
		t.Fatalf("relay dropped %d replies, want exactly 1", n)
	}
	// The retry reply is the healing: without the want bit B would not answer a
	// half it had already settled on, and A would have stayed plaintext.
	if n := seen.Load(); n < 2 {
		t.Fatalf("relay routed %d replies to A, want >= 2 (the retry must draw one)", n)
	}
}

// TestStatusReportsEncryption drives an encrypted round trip and checks the host
// status counts the peer as encrypted and names it "secure".
func TestStatusReportsEncryption(t *testing.T) {
	eA, eB, _ := newEncryptedPair(t)

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	roundTrip(t, conn, "enc")

	srv := newServer(eA)
	defer srv.close()
	st := srv.status()
	if st.EncryptedPeers < 1 {
		t.Fatalf("EncryptedPeers = %d, want >= 1", st.EncryptedPeers)
	}
	if got := st.PeerEncryption[keyName(eB.pub)]; got != encStateSecure {
		t.Fatalf("PeerEncryption[peer] = %q, want %q", got, encStateSecure)
	}
}

// settledSecurePair returns two secureSessions that have exchanged their halves,
// so keys() reports ready on both — a stand-in for an encrypted (peer,
// transport) session without driving a full punch.
func settledSecurePair(t *testing.T, transport byte) (*secureSession, *secureSession) {
	t.Helper()
	privA, pubA, _ := derpclient.Generate()
	privB, pubB, _ := derpclient.Generate()
	a := newSecureSession(nil, transport, privA, pubB)
	b := newSecureSession(nil, transport, privB, pubA)
	boxA, err := a.start()
	if err != nil {
		t.Fatal(err)
	}
	boxB, err := b.start()
	if err != nil {
		t.Fatal(err)
	}
	clearA, ok := privB.OpenFrom(pubA, boxA)
	if !ok {
		t.Fatal("unseal A's half")
	}
	clearB, ok := privA.OpenFrom(pubB, boxB)
	if !ok {
		t.Fatal("unseal B's half")
	}
	if ok, _ := a.respond(clearB); !ok {
		t.Fatal("A rejected B's half")
	}
	if ok, _ := b.respond(clearA); !ok {
		t.Fatal("B rejected A's half")
	}
	return a, b
}

// TestEncryptionState pins the peer-level rule: "secure" only when every live
// session the peer has holds keys. A plaintext live direct session must not be
// masked by an encrypted relay session — the visibility hole the review flagged.
// These inputs are synthetic: peerEncryptions skips a peer with no live session
// entirely (see TestPeerEncryptionsSkipsSessionless), so a live Status never
// asks the classifier about one; the unit test still covers its own contract.
func TestEncryptionState(t *testing.T) {
	peer := derpclient.PublicKey{7}
	encRelay, _ := settledSecurePair(t, secureTransportRelay)
	encDirect, _ := settledSecurePair(t, secureTransportDirect)
	plain := newSecureSession(nil, secureTransportDirect, derpclient.PrivateKey{}, peer) // never settled

	if got := encryptionState(nil, nil); got != encStatePlaintext {
		t.Errorf("no sessions = %q, want plaintext", got)
	}
	if got := encryptionState(&peerConn{peer: peer, secure: encRelay}, nil); got != encStateSecure {
		t.Errorf("encrypted relay = %q, want secure", got)
	}
	if got := encryptionState(&peerConn{peer: peer, secure: plain}, nil); got != encStatePlaintext {
		t.Errorf("plaintext relay = %q, want plaintext", got)
	}
	// Encrypted relay + a live plaintext direct session reads plaintext: the
	// plaintext path is the one carrying data, so it must not be hidden.
	dcPlain := &directConn{peer: peer, sess: newTestSess(t), state: directUp, secure: plain}
	if got := encryptionState(&peerConn{peer: peer, secure: encRelay}, dcPlain); got != encStatePlaintext {
		t.Errorf("encrypted relay + plaintext live direct = %q, want plaintext", got)
	}
	// Both live and encrypted: secure.
	dcEnc := &directConn{peer: peer, sess: newTestSess(t), state: directUp, secure: encDirect}
	if got := encryptionState(&peerConn{peer: peer, secure: encRelay}, dcEnc); got != encStateSecure {
		t.Errorf("encrypted relay + encrypted direct = %q, want secure", got)
	}
	// A direct session that is not live is not considered: it must not downgrade
	// an otherwise-encrypted peer.
	dcDead := &directConn{peer: peer, state: directUp, secure: plain} // sess == nil → !live()
	if got := encryptionState(&peerConn{peer: peer, secure: encRelay}, dcDead); got != encStateSecure {
		t.Errorf("encrypted relay + non-live plaintext direct = %q, want secure", got)
	}
}

// TestRelayRefusesUnencryptedPeer: a relay that drops every ctrlSecure frame
// leaves the handshake unsettleable, and forced encryption must refuse the
// session rather than fall back to plaintext. The open fails; no cleartext
// session is built. Every ctrlSecure frame is dropped in both directions, so
// neither end settles; the shortened handshake timeout keeps the test prompt.
func TestRelayRefusesUnencryptedPeer(t *testing.T) {
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 300 * time.Millisecond
	defer func(d time.Duration) { resendInterval = d }(resendInterval)
	resendInterval = 50 * time.Millisecond

	eA, eB, rs := newEncryptedPair(t)
	rs.mu.Lock()
	rs.dropCtrl = func(_ [32]byte, payload []byte) bool {
		return len(payload) > 1 && payload[1] == ctrlSecure
	}
	rs.mu.Unlock()

	start := time.Now()
	conn, err := eA.OpenStream(eB.PublicKey())
	if err == nil {
		conn.Close()
		t.Fatal("open succeeded without a settled handshake, want refusal")
	}
	if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("open error = %v, want errEncryptionRequired", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("refusal took %v, want it bounded by handshakeTimeout", elapsed)
	}

	// No cleartext session was built, and the refused peer has no live data path,
	// so it is not reported at all: PlaintextPeers stays 0 (forced encryption).
	srv := newServer(eA)
	defer srv.close()
	st := srv.status()
	if st.EncryptedPeers != 0 || st.PlaintextPeers != 0 {
		t.Errorf("EncryptedPeers=%d PlaintextPeers=%d, want 0/0 (a refused peer has no session)", st.EncryptedPeers, st.PlaintextPeers)
	}
	if got, ok := st.PeerEncryption[keyName(eB.pub)]; ok {
		t.Errorf("PeerEncryption[peer] = %q, want absent (no live session)", got)
	}
}

// TestPeerEncryptionsSkipsSessionless: a peer with no live data path (e.g. its
// session was refused) is not reported — otherwise PlaintextPeers would count a
// refused peer as a plaintext session. A live encrypted session reports secure.
func TestPeerEncryptionsSkipsSessionless(t *testing.T) {
	peer := derpclient.PublicKey{7}
	encRelay, _ := settledSecurePair(t, secureTransportRelay)
	plain := newSecureSession(nil, secureTransportRelay, derpclient.PrivateKey{}, peer)

	e := &engine{
		peers: map[derpclient.PublicKey]*peerConn{peer: {peer: peer, secure: plain}},
		log:   slog.Default(),
	}
	if got, ok := e.peerEncryptions()[keyName(peer)]; ok {
		t.Fatalf("session-less peer reported as %q, want absent", got)
	}

	// A live session is reported, and it is always secure under forced
	// encryption.
	e.peers[peer] = &peerConn{peer: peer, secure: encRelay, sess: newTestSess(t)}
	if got := e.peerEncryptions()[keyName(peer)]; got != encStateSecure {
		t.Fatalf("live encrypted peer = %q, want %q", got, encStateSecure)
	}
}

// TestEnsureSessionInboundDoesNotBlock: the pump path (wait=false) must never
// wait on the relay round trip, or one non-negotiating peer stalls inbound
// routing for every peer. With a large handshakeTimeout a non-blocking call on
// an unsettled adapter returns at once with a refusal, not after the timeout.
func TestEnsureSessionInboundDoesNotBlock(t *testing.T) {
	defer func(d time.Duration) { handshakeTimeout = d }(handshakeTimeout)
	handshakeTimeout = 30 * time.Second // a blocking call would take this long

	e := &engine{
		peers:  make(map[derpclient.PublicKey]*peerConn),
		secure: make(map[secureKey]*secureSession),
		gone:   make(map[derpclient.PublicKey]bool),
		log:    slog.Default(),
	}
	peer := derpclient.PublicKey{9}
	priv, _, _ := derpclient.Generate()
	pc := &peerConn{
		e:       e,
		peer:    peer,
		inbound: make(chan []byte, inboundQueueSize),
		closeCh: make(chan struct{}),
		secure:  newSecureSession(nil, secureTransportRelay, priv, peer),
	}

	start := time.Now()
	_, err := pc.ensureSession(true, false)
	if !errors.Is(err, errEncryptionRequired) {
		t.Fatalf("inbound call error = %v, want errEncryptionRequired", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("inbound call took %v with handshakeTimeout=%v: it blocked on the round trip", elapsed, handshakeTimeout)
	}
}
