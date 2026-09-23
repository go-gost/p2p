package p2p

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
}
