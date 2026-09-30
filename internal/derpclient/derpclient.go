// Package derpclient implements the minimal client side of the DERP protocol
// (Tailscale's Designated Encrypted Relay for Packets) over the WebSocket
// transport, enough to act as a p2p rendezvous/relay client against the
// official derper binary.
//
// Transport is WebSocket-DERP: standard RFC6455 upgrade with subprotocol
// "derp", DERP binary frames carried in WebSocket binary messages. This is
// the path the official derper serves unconditionally
// (derpserver.AddWebSocketSupport) and is what keeps a self-hosted relay
// deployable behind WebSocket-capable proxies/CDNs (e.g. Cloudflare). The
// native "Upgrade: DERP" hijack transport and Derp-Fast-Start are NOT
// implemented: FastStart skips the HTTP 101 response and breaks every L7
// proxy; the raw framing saves nothing that matters here.
//
// Wire protocol reference: tailscale.com/derp@v1.102.3 (derp.go). A frame is
// a 1-byte type + 4-byte big-endian length. Unknown frame types are silently
// skipped — same forward-compat behavior as the reference client, whose recv
// switch has no default case.
//
// Identity is a curve25519 keypair (same shape as Tailscale node keys): the
// public key is the address packets are routed to, and ClientInfo is
// NaCl-boxed to the server key to prove possession of the private key.
//
// Escape hatch: if a future derper breaks interop and the fix costs more
// than a dependency bump, replace this package by importing
// tailscale.com/derp(+derphttp) as a client instead (measured 2026-09-05:
// its import closure is ~289 packages incl. tailcfg/kubetypes coupling —
// the reason this subset exists).
package derpclient

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// ErrPeerGone is returned by Recv when the DERP server reports that a peer we
// were sending to has disconnected; the returned source is that peer's key.
var ErrPeerGone = errors.New("derpclient: peer gone")

// Wire constants mirrored from tailscale.com/derp@v1.102.3 (do not invent).
const (
	// Magic is the 8-byte DERP magic sent in the FrameServerKey greeting.
	Magic = "DERP🔑"
	// ProtocolVersion is the client protocol version (v2 = RecvPacket
	// carries the 32-byte source key).
	ProtocolVersion = 2
	// MaxPacketSize is the maximum size of packet bytes in SendPacket.
	MaxPacketSize = 64 << 10

	frameHeaderLen = 1 + 4
	keyLen         = 32
	nonceLen       = 24
	maxInfoLen     = 1 << 20
	maxFrameLen    = keyLen + MaxPacketSize + nonceLen + 8 // generous bound for any frame we accept
)

// Frame types from derp.go@v1.102.3.
const (
	frameServerKey   = 0x01 // 8B magic + 32B public key + (0+ bytes future use)
	frameClientInfo  = 0x02 // 32B pub key + 24B nonce + naclbox(json)
	frameServerInfo  = 0x03 // 24B nonce + naclbox(json)
	frameSendPacket  = 0x04 // 32B dest pub key + packet bytes
	frameRecvPacket  = 0x05 // v2: 32B src pub key + packet bytes
	frameKeepAlive   = 0x06 // no payload, no-op
	framePeerGone    = 0x08 // 32B pub key + 1B reason (informational; we ignore)
	framePeerPresent = 0x09 // 32B+ pub key of connected peer (informational; we ignore)
	framePing        = 0x12 // 8B payload, echoed back as pong
	framePong        = 0x13 // 8B payload, contents of the ping replied to
)

// PrivateKey is a curve25519 private key (raw 32 bytes, same wire format as
// a Tailscale node private key).
type PrivateKey [keyLen]byte

// writeTimeout bounds one frame write (see writeFrame). It is a var so tests
// can shorten it. The value is generous on purpose: it exists to catch a path
// that is gone, not to police a slow one — a healthy frame write is
// sub-millisecond, and the DERP server's own keepalives keep a live path busy.
var writeTimeout = 10 * time.Second

// PublicKey is a curve25519 public key; its base64 form is the peer address.
type PublicKey [keyLen]byte

// Generate creates a new random keypair.
func Generate() (PrivateKey, PublicKey, error) {
	var priv PrivateKey
	if _, err := rand.Read(priv[:]); err != nil {
		return priv, PublicKey{}, err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, PublicKey{}, err
	}
	var p PublicKey
	copy(p[:], pub)
	return priv, p, nil
}

// Public derives the public key.
func (k PrivateKey) Public() PublicKey {
	var p PublicKey
	b, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		panic("derpclient: invalid private key") // only possible for a zero/invalid key
	}
	copy(p[:], b)
	return p
}

// SealTo boxes cleartext to p, authenticated from k. The result is a 24-byte
// nonce followed by the box value — identical layout to
// tailscale.com/types/key NodePrivate.SealTo.
func (k PrivateKey) SealTo(p PublicKey, cleartext []byte) []byte {
	var nonce [nonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		panic("derpclient: rand failure") // crypto/rand never fails on supported platforms
	}
	return box.Seal(nonce[:], cleartext, &nonce, (*[keyLen]byte)(&p), (*[keyLen]byte)(&k))
}

// OpenFrom opens a box created by SealTo(p, ...) using k.
func (k PrivateKey) OpenFrom(p PublicKey, ciphertext []byte) ([]byte, bool) {
	if len(ciphertext) < nonceLen {
		return nil, false
	}
	var nonce [nonceLen]byte
	copy(nonce[:], ciphertext)
	return box.Open(nil, ciphertext[nonceLen:], &nonce, (*[keyLen]byte)(&p), (*[keyLen]byte)(&k))
}

// clientInfo is the JSON inside FrameClientInfo. Fields mirror
// derp.ClientInfo@v1.102.3; unknown server-side fields are irrelevant to us.
type clientInfo struct {
	Version     int    `json:"version"`
	CanAckPings bool   `json:"canAckPings"`
	AppName     string `json:",omitempty"`
}

// serverInfo is the JSON inside FrameServerInfo.
type serverInfo struct {
	TokenBucketBytesPerSecond int `json:",omitempty"`
	TokenBucketBytesBurst     int `json:",omitempty"`
}

// Client is a WebSocket-DERP connection. All methods are safe for concurrent
// use; Recv is intended to be called from a single reader goroutine.
type Client struct {
	ws        *websocket.Conn
	conn      net.Conn
	cancel    context.CancelFunc // cancels the NetConn's backing context on Close
	br        *bufio.Reader
	bw        *bufio.Writer
	priv      PrivateKey
	pub       PublicKey
	serverKey PublicKey

	wmu sync.Mutex // serializes all frame writes (including pong replies from Recv)

	// recvAt (unix nanos) and recvN are stamped by Recv on every frame read, and
	// recvAt once more when the handshake completes (a completed handshake is
	// the first proof the path carries frames). A relay path can die without the
	// WebSocket noticing — writes are buffered and nothing errors — so the only
	// local evidence of a live path is inbound frames, and the engine both
	// reports the age of the newest one and reconnects when it goes stale.
	recvAt atomic.Int64
	recvN  atomic.Int64

	// pongAt (unix nanos) and pongN record the answers to our pings. A relay
	// path that has gone dead while TCP still looks open carries no frames at
	// all, healthy or not, so "nothing received" proves nothing on its own —
	// the round trip is what tells the two apart.
	pongAt atomic.Int64
	pongN  atomic.Int64

	// dropPong is a debug-only fault injection (p2p.FaultsConfig.DropPong): pong
	// handling is swallowed, both the answer to the relay's ping and the stamp
	// that records an arriving one, so a relay that is answering reads as silent
	// to the engine's ping watchdog. Set once by the caller before Recv runs; the
	// fault config is startup-only, never a runtime switch.
	dropPong atomic.Bool
}

// SetDropPong turns the pong-swallowing debug fault on or off (see the field).
// A no-op by default, and never reachable from the network.
func (c *Client) SetDropPong(v bool) { c.dropPong.Store(v) }

// LastRecv returns when the most recent frame arrived (zero if none has).
func (c *Client) LastRecv() time.Time {
	at := c.recvAt.Load()
	if at == 0 {
		return time.Time{}
	}
	return time.Unix(0, at)
}

// RecvFrames returns how many frames have arrived, so a caller can tell a
// fresh arrival from a stale LastRecv.
func (c *Client) RecvFrames() int64 { return c.recvN.Load() }

// LastPong returns when the most recent pong arrived (zero if none has).
func (c *Client) LastPong() time.Time {
	at := c.pongAt.Load()
	if at == 0 {
		return time.Time{}
	}
	return time.Unix(0, at)
}

// Pongs returns how many pongs have arrived.
func (c *Client) Pongs() int64 { return c.pongN.Load() }

// Dial connects to the DERP server at rawURL ("wss://host/derp", or ws://
// for plaintext dev deployments), completes the DERP handshake, and returns
// a ready client. tlsCfg may be nil for the system defaults; SSL_CERT_FILE
// based custom roots work with nil too.
func Dial(ctx context.Context, rawURL string, priv PrivateKey, tlsCfg *tls.Config) (*Client, error) {
	dialOpts := &websocket.DialOptions{
		Subprotocols:    []string{"derp"},
		CompressionMode: websocket.CompressionDisabled, // matches derper; payload is incompressible anyway
	}
	if tlsCfg != nil {
		dialOpts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	}
	ws, resp, err := websocket.Dial(ctx, rawURL, dialOpts)
	if err != nil {
		return nil, fmt.Errorf("derpclient: websocket dial: %w", err)
	}
	if resp != nil && resp.Header.Get("Sec-Websocket-Protocol") != "derp" {
		ws.Close(websocket.StatusPolicyViolation, "server did not accept the derp subprotocol")
		return nil, errors.New("derpclient: server did not accept subprotocol derp")
	}

	c := &Client{
		ws:   ws,
		priv: priv,
		pub:  priv.Public(),
	}
	// The NetConn's backing context must outlive Dial: the caller cancels the
	// dial context as soon as Dial returns, which would kill the read loop.
	// Own a separate context tied to Close.
	connCtx, cancel := context.WithCancel(context.Background())
	c.conn = websocket.NetConn(connCtx, ws, websocket.MessageBinary)
	c.cancel = cancel
	c.br = bufio.NewReader(c.conn)
	c.bw = bufio.NewWriter(c.conn)

	if err := c.handshake(); err != nil {
		c.cancel()
		ws.Close(websocket.StatusInternalError, "handshake failed")
		return nil, err
	}
	// The handshake is the first frame this connection carried, so it starts the
	// inbound clock: a connection that never hears another thing is measurable
	// instead of looking like one that has simply not been read yet.
	c.recvAt.Store(time.Now().UnixNano())
	return c, nil
}

// PublicKey returns this client's public key (the address others send to).
func (c *Client) PublicKey() PublicKey { return c.pub }

// ServerPublicKey returns the server's public key learned from the greeting.
func (c *Client) ServerPublicKey() PublicKey { return c.serverKey }

// handshake mirrors the reference client: read FrameServerKey, send
// FrameClientInfo (boxed to the server key), read FrameServerInfo.
func (c *Client) handshake() error {
	// FrameServerKey: magic + server public key; tolerate trailing bytes
	// ("0+ bytes future use").
	t, body, err := c.readFrame()
	if err != nil {
		return err
	}
	if t != frameServerKey || len(body) < 8+keyLen || string(body[:8]) != Magic {
		return errors.New("derpclient: bad server greeting")
	}
	copy(c.serverKey[:], body[8:8+keyLen])

	info, err := json.Marshal(clientInfo{Version: ProtocolVersion, CanAckPings: true})
	if err != nil {
		return err
	}
	msgbox := c.priv.SealTo(c.serverKey, info)
	buf := make([]byte, 0, keyLen+len(msgbox))
	buf = append(buf, c.pub[:]...)
	buf = append(buf, msgbox...)
	if err := c.writeFrame(frameClientInfo, buf); err != nil {
		return err
	}

	t, body, err = c.readFrame()
	if err != nil {
		return err
	}
	if t != frameServerInfo {
		return fmt.Errorf("derpclient: unexpected frame 0x%02x waiting for ServerInfo", t)
	}
	clear, ok := c.priv.OpenFrom(c.serverKey, body)
	if !ok {
		return errors.New("derpclient: cannot open ServerInfo box")
	}
	var si serverInfo
	if err := json.Unmarshal(clear, &si); err != nil {
		return fmt.Errorf("derpclient: bad ServerInfo json: %w", err)
	}
	// Token bucket values are advisory; we do not implement client-side rate
	// limiting (the server enforces its own).
	return nil
}

// SendPacket sends pkt to the peer addressed by dst (max MaxPacketSize).
func (c *Client) SendPacket(dst PublicKey, pkt []byte) error {
	if len(pkt) > MaxPacketSize {
		return fmt.Errorf("derpclient: packet %d bytes exceeds MaxPacketSize %d", len(pkt), MaxPacketSize)
	}
	buf := make([]byte, 0, keyLen+len(pkt))
	buf = append(buf, dst[:]...)
	buf = append(buf, pkt...)
	return c.writeFrame(frameSendPacket, buf)
}

// KeepAlive sends an empty keep-alive frame.
func (c *Client) KeepAlive() error {
	return c.writeFrame(frameKeepAlive, nil)
}

// Pong replies to a ping (the engine does not use Ping; kept for the test
// server and completeness).
func (c *Client) pong(payload []byte) error {
	return c.writeFrame(framePong, payload)
}

// Ping sends an 8-byte ping, which the server echoes back as a pong. It is the
// engine's liveness probe: a relay path can die while the WebSocket still looks
// open (writes buffer, reads park), and a quiet path carries no frames either
// way, so only a round trip tells a quiet relay from a dead one. The answer is
// stamped by Recv and reported by LastPong.
func (c *Client) Ping() error {
	var payload [8]byte
	if _, err := rand.Read(payload[:]); err != nil {
		return err
	}
	return c.writeFrame(framePing, payload[:])
}

// Recv blocks until a packet arrives and returns its source key and bytes.
// KeepAlive, PeerPresent, unknown frame types, and Pong replies are consumed
// internally; FramePing is answered with FramePong. A FramePeerGone returns
// ErrPeerGone with the departed peer's key as the source.
func (c *Client) Recv() (src PublicKey, pkt []byte, err error) {
	for {
		t, body, err := c.readFrame()
		if err != nil {
			return PublicKey{}, nil, err
		}
		c.recvAt.Store(time.Now().UnixNano())
		c.recvN.Add(1)
		switch t {
		case frameRecvPacket:
			if len(body) < keyLen {
				return PublicKey{}, nil, errors.New("derpclient: short RecvPacket")
			}
			copy(src[:], body[:keyLen])
			return src, body[keyLen:], nil
		case framePing:
			// A ping from the relay is answered unless the pong fault is on: a
			// relay that never hears back from us gives up on the connection, so
			// the fault looks like a silent relay from both ends — which is what
			// it is reproducing.
			if len(body) > 0 && !c.dropPong.Load() {
				c.pong(body)
			}
		case framePeerGone:
			// A peer we sent to disconnected; surface it so the caller can drop
			// the session instead of probing a dead peer.
			if len(body) < keyLen {
				continue
			}
			copy(src[:], body[:keyLen])
			return src, nil, ErrPeerGone
		case frameKeepAlive, framePeerPresent, frameServerKey, frameServerInfo:
			// no-op for us
		case framePong:
			// The answer to a Ping: the round trip is the engine's evidence
			// that the path is alive, so it is stamped rather than ignored.
			if c.dropPong.Load() {
				// Fault injection: the answer arrives and is thrown away, so the
				// engine's ping watchdog declares a live relay dead.
				continue
			}
			c.pongAt.Store(time.Now().UnixNano())
			c.pongN.Add(1)
		default:
			// Unknown frame type: skip (forward compatibility).
		}
	}
}

func (c *Client) readFrame() (t byte, body []byte, err error) {
	var hdr [frameHeaderLen]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	t = hdr[0]
	l := binary.BigEndian.Uint32(hdr[1:])
	if l > maxFrameLen {
		return 0, nil, fmt.Errorf("derpclient: frame type 0x%02x too large (%d)", t, l)
	}
	body = make([]byte, l)
	if _, err := io.ReadFull(c.br, body); err != nil {
		return 0, nil, err
	}
	return t, body, nil
}

func (c *Client) writeFrame(t byte, body []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	// Bound the write. A half-open path — the phone's Wi-Fi/cellular switch,
	// where TCP still looks open and writes sink into the kernel buffer — must
	// surface here as an error, or the write parks inside wmu and every other
	// writer (the engine's keepalive, the pong replies) waits on it: the engine
	// then never sees a failure and never reconnects. The deadline is per write,
	// so a live but slow path is not penalised.
	c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer func() { _ = c.conn.SetWriteDeadline(time.Time{}) }()
	var hdr [frameHeaderLen]byte
	hdr[0] = t
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(body)))
	if _, err := c.bw.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := c.bw.Write(body); err != nil {
		return err
	}
	return c.bw.Flush()
}

// Close closes the connection.
func (c *Client) Close() error {
	c.cancel()
	c.ws.Close(websocket.StatusNormalClosure, "")
	return c.conn.Close()
}
