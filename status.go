package p2p

// PeerPunch is one peer's hole-punch history. The process-wide
// PunchAttempts/PunchSuccess cannot say which peer is re-punching, which is the
// question a direct session that keeps dying raises.
type PeerPunch struct {
	Attempts int64 // punch rounds started for this peer
	Ups      int64 // rounds that reached a live direct session
	Drops    int64 // live direct sessions that ended (and re-punched)
}

// Status is a point-in-time snapshot of an endpoint: the live tunnel count and
// the transport counters behind it. A stub-mode endpoint (no relay configured)
// reports zeros for the transport fields.
type Status struct {
	Tunnels       int   // active tunnels held by this endpoint (pending records included)
	DirectPeers   int   // gauge: peers with a live direct session
	DerpPeers     int   // gauge: peers on relay only (no live direct session)
	PunchAttempts int64 // counter
	PunchSuccess  int64 // counter: attempts that reached direct
	StreamsDirect int64 // counter
	StreamsDerp   int64 // counter
	// PeerTransports names each connected peer's current path, keyed by base64
	// public key. A peer with no session at all is absent: every value
	// describes a peer that is reachable, and says whether it rides a
	// hole-punched session or, if not, the most specific reason available —
	// so DirectPeers/DerpPeers are its counts.
	//
	// One of:
	//
	//	"direct"           a live hole-punched session
	//	"punching"         a punch for this peer is in flight
	//	"failed"           this peer's punch failed (usually a symmetric NAT)
	//	"derp"             on the relay, with nothing in the way of a punch
	//	"disabled"         the direct path is off (Config.Direct)
	//	"no-candidates"    no STUN server and no IPv6 egress: nothing to punch with
	//	"stun-unreachable" STUN is configured but not answering, and there is no
	//	                   IPv6 egress to fall back on
	//
	// The gRPC transport does not carry it: its proto is frozen, so plugin
	// clients see the counts only.
	PeerTransports map[string]string

	// RelayConnected reports whether the relay transport holds a live
	// connection, and RelayError the last dial failure (empty while connected).
	//
	// None of the fields above can show a relay outage: a live hole-punched
	// session keeps every gauge and counter healthy while the relay is
	// unreachable, and the direct session is independent of the DERP transport.
	//
	// In-process only, like PeerTransports: the gRPC transport's proto is
	// frozen, so plugin clients see neither.
	RelayConnected bool
	RelayError     string

	// PeerPunches is each connected peer's own punch history, keyed by base64
	// public key. A peer that has never attempted a direct path is absent.
	// In-process only, like PeerTransports.
	PeerPunches map[string]PeerPunch

	// EncryptedPeers counts connected peers all of whose live sessions settled
	// encrypted; PlaintextPeers counts the rest (the peer predates encryption,
	// the handshake timed out, or a live direct session is plaintext). A relay
	// that drops the handshake can force a session to plaintext, so a nonzero
	// PlaintextPeers is the signal to watch.
	EncryptedPeers int
	PlaintextPeers int
	// PeerEncryption names each connected peer's session state, keyed by base64
	// public key: "secure" only when every live session the peer has (the relay
	// session, and the direct session while one is live) settled encrypted, else
	// "plaintext". The rule errs toward the alarm: a plaintext direct path is not
	// masked by an encrypted relay session, and an unsettled session reads as
	// plaintext. In-process only, like PeerTransports.
	PeerEncryption map[string]string
}
