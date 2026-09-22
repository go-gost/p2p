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
}
