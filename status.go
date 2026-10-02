package p2p

import "time"

// PeerDiagnostic is one connected peer's live state: where its traffic goes, why,
// and enough detail (the last error, the dialled endpoint, the ages) to diagnose
// it without raising the log level. It supersedes the old punch counters, which
// it carries.
type PeerDiagnostic struct {
	// Path is the current transport word: "direct", "punching", "failed",
	// "derp", "disabled", "no-candidates" or "stun-unreachable".
	Path string
	// Reason is the host-wide cause when it outranks this peer's own round
	// ("no-candidates", "stun-unreachable", "disabled"), else empty.
	Reason string
	// State is the punch state machine: "none", "attempting", "up" or "backoff".
	State string
	// Failed reports a punch round that has failed (sticky).
	Failed bool
	// LastError is the last punch failure's reason (empty after a success).
	LastError string
	// PeerAddr is the endpoint dialled for the direct path (empty until a round
	// dials). Candidates is how many the peer announced.
	PeerAddr   string
	Candidates int
	// Caps is the peer's advertised capabilities ("ipv6", "tightKeepalive").
	Caps []string
	// SessionAge is how long the live direct session has been up (0 when none);
	// LastRecvAge is how long since this host last saw *traffic* from the peer,
	// on either path: an inbound relay packet, or bytes off a stream (relay or
	// direct).
	//
	// "Traffic", not "a frame": smux keepalive NOPs are consumed inside smux and
	// never reach the pump, so a peer that is connected and merely idle ages.
	// Read it as "this peer is this quiet", never as "the path is down" — the
	// sessions' own ages and liveness say that. 0 when nothing was ever seen.
	SessionAge  time.Duration
	LastRecvAge time.Duration
	// Attempts/Ups/Drops are the peer's punch history (what PeerPunch held).
	Attempts int64
	Ups      int64
	Drops    int64
	// RelayRebuilds counts this peer's relay mux sessions built after the first,
	// and PeerRekeys those torn down because the peer changed its secure half —
	// the one teardown neither side causes from its own config. Both are 0 for a
	// healthy pair, and a pair that rebuilds repeatedly is flapping: the field
	// case was five peer-rekeyed teardowns in twelve minutes, which showed up
	// only by grepping the log.
	RelayRebuilds int64
	PeerRekeys    int64
	// Trace is the peer's recent punch history: short human-readable lines, the
	// oldest first, capped at the ring's size (the newest are kept). Nil for a
	// peer with no direct punch state (a relay-only peer).
	Trace []string
}

// DirectConfig is the direct path a host is running with. It answers "why is
// this host not punching?" without reading the engine: a caller hands p2p a
// Config, and the engine narrows it (an embedder's STUN probe that fails leaves
// Stun empty, an egress without IPv6 leaves IPv6 false), so the configured
// values are not what the host acts on.
type DirectConfig struct {
	// Direct is the master switch as the host resolved it (Config.Direct).
	Direct bool
	// Stun is the STUN server the engine holds ("host:port"), empty when none.
	Stun string
	// StunFailed is whether the last IPv4 candidate collection failed.
	StunFailed bool
	// IPv6 is whether a usable global IPv6 egress was found (or configured).
	IPv6 bool
	// Reason is the host-wide transport word: "disabled", "no-candidates",
	// "stun-unreachable", or "" while a punch is possible.
	Reason string
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
	//	"peer-direct-off"   the peer has the direct path off (its Config.Direct),
	//	                   so no round here could succeed — nothing is broken, and
	//	                   it outranks "failed" so the pair is not read as a
	//	                   symmetric NAT it is not
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

	// DirectConfig is the direct path this host is *running* with, not the one
	// it was configured with: Direct is Config.Direct, Stun is the server the
	// engine actually holds (an embedder that probed one and got no answer
	// hands p2p an empty one), StunFailed is whether its last collection
	// failed, and IPv6 is whether a global IPv6 egress was found. A host that
	// never punches is explained by these four values alone.
	//
	// Reason is the host-wide word the transport reports ("disabled",
	// "no-candidates", "stun-unreachable", or "" while a punch is possible).
	// In-process only: the gRPC transport's proto is frozen.
	DirectConfig DirectConfig

	// PeerDiagnostics is each connected peer's live state, keyed by base64
	// public key. The gRPC transport carries it as the repeated
	// peer_diagnostics message (each entry keyed by the base64 key).
	PeerDiagnostics map[string]PeerDiagnostic

	// EncryptedPeers counts connected peers whose live sessions settled
	// encrypted. Encryption is forced: a session that does not settle is refused,
	// never built as plaintext, so a live session is always encrypted and a live
	// peer is always counted here. Both fields are retained for API/wire
	// compatibility; the plaintext data path they once distinguished no longer
	// occurs.
	EncryptedPeers int
	PlaintextPeers int
	// PeerEncryption names each connected peer's session state, keyed by base64
	// public key: "secure" when every live session the peer has (the relay
	// session, and the direct session while one is live) settled encrypted, else
	// "plaintext". In-process only, like PeerTransports. With forced encryption a
	// peer's live sessions are always encrypted, so any live session reports
	// "secure"; the "plaintext" value is retained for compatibility and is not
	// produced for a live session (it can only describe a peer whose handshake
	// was refused, and which therefore has no data path).
	PeerEncryption map[string]string
}
