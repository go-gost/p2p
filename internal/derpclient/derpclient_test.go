package derpclient

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// frameReader/frameWriter mirror the client's frame I/O for the test
// servers, over the raw WS byte stream.

type frameReader struct{ r io.Reader }

func newFrameReader(r io.Reader) *frameReader { return &frameReader{r: r} }

type frameWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func newFrameWriter(w io.Writer) *frameWriter { return &frameWriter{w: w} }

func writeFrame(w *frameWriter, t byte, body []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var hdr [frameHeaderLen]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if _, err := w.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.w.Write(body)
	return err
}

func readFrame(fr *frameReader) (byte, []byte, error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return 0, nil, err
	}
	t := hdr[0]
	l := binary.BigEndian.Uint32(hdr[1:])
	if l > maxFrameLen {
		return 0, nil, errors.New("frame too large")
	}
	body := make([]byte, l)
	if _, err := io.ReadFull(fr.r, body); err != nil {
		return 0, nil, err
	}
	return t, body, nil
}

// miniServer implements the server side of the DERP subset we speak, for
// unit tests. It performs the same handshake as the official derper's
// WebSocket path (coder/websocket Accept with subprotocol "derp", binary
// messages) and then relays each SendPacket back to the sender as a
// RecvPacket — enough to prove framing, handshake crypto, and routing shape.
// Full relay behavior is verified against a real derper in the e2e.
type miniServer struct {
	srv  *httptest.Server
	priv PrivateKey
	pub  PublicKey
}

func startMiniServer(t *testing.T) (*miniServer, string) {
	t.Helper()
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	m := &miniServer{priv: priv, pub: pub}
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols:    []string{"derp"},
			OriginPatterns:  []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		if ws.Subprotocol() != "derp" {
			ws.Close(websocket.StatusPolicyViolation, "must speak derp")
			return
		}
		conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		m.serveConn(newFrameReader(conn), newFrameWriter(conn))
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m, "ws://" + m.srv.Listener.Addr().String() + "/derp"
}

func (m *miniServer) serveConn(br *frameReader, bw *frameWriter) {
	greeting := append(append([]byte{}, Magic...), m.pub[:]...)
	if err := writeFrame(bw, frameServerKey, greeting); err != nil {
		return
	}
	var clientPub PublicKey
	for {
		t, body, err := readFrame(br)
		if err != nil {
			return
		}
		switch t {
		case frameClientInfo:
			if len(body) < keyLen {
				return
			}
			copy(clientPub[:], body[:keyLen])
			clear, ok := m.priv.OpenFrom(clientPub, body[keyLen:])
			if !ok {
				return // bad box: drop connection like the real server
			}
			var ci clientInfo
			if json.Unmarshal(clear, &ci) != nil || ci.Version != ProtocolVersion {
				return
			}
			resp, _ := json.Marshal(serverInfo{})
			if err := writeFrame(bw, frameServerInfo, m.priv.SealTo(clientPub, resp)); err != nil {
				return
			}
		case frameSendPacket:
			// relay echo: RecvPacket(src = sender)
			if len(body) < keyLen {
				return
			}
			pkt := append(append([]byte{}, clientPub[:]...), body[keyLen:]...)
			if err := writeFrame(bw, frameRecvPacket, pkt); err != nil {
				return
			}
		case framePing:
			writeFrame(bw, framePong, body)
		default:
			// skip unknown
		}
	}
}

func TestGenerateAndBox(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if priv.Public() != pub {
		t.Fatal("Public() mismatch")
	}
	msg := []byte("hello")
	boxed := priv.SealTo(pub, msg)
	clear, ok := priv.OpenFrom(pub, boxed)
	if !ok || string(clear) != "hello" {
		t.Fatalf("box roundtrip failed: ok=%v clear=%q", ok, clear)
	}
	boxed[len(boxed)-1] ^= 0xff
	if _, ok := priv.OpenFrom(pub, boxed); ok {
		t.Fatal("tampered box opened")
	}
	_, other, _ := Generate()
	if _, ok := priv.OpenFrom(other, boxed); ok {
		t.Fatal("box opened under wrong key")
	}
}

func TestHandshakeAndPacketRoundTrip(t *testing.T) {
	m, url := startMiniServer(t)
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, url, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.PublicKey() != pub {
		t.Fatal("client pubkey mismatch")
	}
	if c.ServerPublicKey() != m.pub {
		t.Fatal("server pubkey not learned from greeting")
	}

	payload := []byte("ping-packet")
	if err := c.SendPacket(pub, payload); err != nil {
		t.Fatal(err)
	}
	src, pkt, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if src != pub {
		t.Fatalf("recv src = %v, want %v", src, pub)
	}
	if string(pkt) != "ping-packet" {
		t.Fatalf("recv payload = %q", pkt)
	}
}

func TestBadMagicRejected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"derp"}, OriginPatterns: []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		bw := newFrameWriter(conn)
		bad := append([]byte("WRONG\x00\x00"), make([]byte, keyLen)...)
		writeFrame(bw, frameServerKey, bad)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	priv, _, _ := Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, "ws://"+srv.Listener.Addr().String()+"/derp", priv, nil); err == nil {
		t.Fatal("Dial succeeded with a bad server greeting")
	}
}

func TestUnknownFramesSkipped(t *testing.T) {
	// The server injects unknown frame types between the handshake and the
	// awaited packet; the client must skip them and still deliver it.
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"derp"}, OriginPatterns: []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		br := newFrameReader(conn)
		bw := newFrameWriter(conn)
		priv, pub, _ := Generate()
		greeting := append(append([]byte{}, Magic...), pub[:]...)
		writeFrame(bw, frameServerKey, greeting)
		for {
			ft, body, err := readFrame(br)
			if err != nil {
				return
			}
			if ft != frameClientInfo {
				continue
			}
			clientPub := PublicKey{}
			copy(clientPub[:], body[:keyLen])
			if _, ok := priv.OpenFrom(clientPub, body[keyLen:]); !ok {
				return
			}
			resp, _ := json.Marshal(serverInfo{})
			writeFrame(bw, frameServerInfo, priv.SealTo(clientPub, resp))
			writeFrame(bw, 0x7e, []byte("junk"))
			writeFrame(bw, 0x7f, nil)
			writeFrame(bw, frameKeepAlive, nil)
			pkt := append(append([]byte{}, clientPub[:]...), []byte("after-unknown")...)
			writeFrame(bw, frameRecvPacket, pkt)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	priv, _, _ := Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, "ws://"+srv.Listener.Addr().String()+"/derp", priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, pkt, err := c.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt) != "after-unknown" {
		t.Fatalf("payload after unknown frames = %q", pkt)
	}
}

func TestBadServerInfoBoxRejected(t *testing.T) {
	// ServerInfo sealed under a different key than the greeting must be
	// rejected.
	mux := http.NewServeMux()
	mux.HandleFunc("/derp", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			Subprotocols: []string{"derp"}, OriginPatterns: []string{"*"},
			CompressionMode: websocket.CompressionDisabled,
		})
		if err != nil {
			return
		}
		defer ws.Close(websocket.StatusInternalError, "bye")
		conn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
		br := newFrameReader(conn)
		bw := newFrameWriter(conn)
		other, _, _ := Generate()            // seals ServerInfo with this key...
		greetPriv, greetPub, _ := Generate() // ...but greets with another
		greeting := append(append([]byte{}, Magic...), greetPub[:]...)
		writeFrame(bw, frameServerKey, greeting)
		for {
			ft, body, err := readFrame(br)
			if err != nil {
				return
			}
			if ft != frameClientInfo {
				continue
			}
			clientPub := PublicKey{}
			copy(clientPub[:], body[:keyLen])
			if _, ok := greetPriv.OpenFrom(clientPub, body[keyLen:]); !ok {
				return
			}
			resp, _ := json.Marshal(serverInfo{})
			writeFrame(bw, frameServerInfo, other.SealTo(clientPub, resp)) // wrong sender key
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	priv, _, _ := Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Dial(ctx, "ws://"+srv.Listener.Addr().String()+"/derp", priv, nil); err == nil {
		t.Fatal("Dial succeeded with a ServerInfo box under the wrong key")
	}
}

func TestOversizedPacketRejected(t *testing.T) {
	m, url := startMiniServer(t)
	priv, pub, _ := Generate()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, url, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.SendPacket(pub, make([]byte, MaxPacketSize+1)); err == nil {
		t.Fatal("oversized packet accepted")
	}
	_ = m
}
