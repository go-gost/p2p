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
	// public key: "direct" when the peer has a live direct session, "derp"
	// otherwise. A peer with no session at all is absent. It says where the
	// next stream would go, which is what a caller showing per-peer state
	// wants — one of DirectPeers/DerpPeers counts, per key.
	//
	// The gRPC transport does not carry it: its proto is frozen, so plugin
	// clients see the counts only.
	PeerTransports map[string]string
}
