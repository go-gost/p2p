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

	mu       sync.Mutex
	clients  map[[32]byte]*relayClient
	dropData bool // when true, drop 0x01 data frames (control still flows)
}

func (s *relayServer) setDropData(v bool) {
	s.mu.Lock()
	s.dropData = v
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
			s.mu.Unlock()
			if rc == nil {
				continue // unknown destination: drop like the real server
			}
			if drop {
				continue // drop data frames, keep control frames flowing
			}
			pkt := make([]byte, 0, 32+len(payload))
			pkt = append(pkt, myPub[:]...)
			pkt = append(pkt, payload...)
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
