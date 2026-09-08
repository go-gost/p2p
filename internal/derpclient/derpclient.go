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
}

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
		switch t {
		case frameRecvPacket:
			if len(body) < keyLen {
				return PublicKey{}, nil, errors.New("derpclient: short RecvPacket")
			}
			copy(src[:], body[:keyLen])
			return src, body[keyLen:], nil
		case framePing:
			if len(body) > 0 {
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
		case frameKeepAlive, framePeerPresent, framePong, frameServerKey, frameServerInfo:
			// no-op for us
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
