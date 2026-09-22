package p2p

import "errors"

// Sentinel errors returned by the endpoint and the host seam. A transport maps
// them to its own error shape (gRPC codes today); an in-process caller matches
// them with errors.Is. Errors that carry a cause — a failed peer open, a
// rejected configuration — wrap one, so the message stays useful while the
// sentinel keeps the classification.
var (
	// ErrInvalidNetwork reports a network the tunnel protocol does not define:
	// anything other than tcp or udp.
	ErrInvalidNetwork = errors.New("p2p: invalid network")
	// ErrInvalidPeer reports a peer string that does not fit the mode: a
	// host:port in stub mode, a base64 public key in DERP mode.
	ErrInvalidPeer = errors.New("p2p: invalid peer")
	// ErrUnknownTunnel reports a tunnel id that was never issued or has been
	// reclaimed by the pending GC.
	ErrUnknownTunnel = errors.New("p2p: unknown tunnel")
	// ErrTunnelAttached reports a second carrier for a tunnel that already has
	// one: an id is single use.
	ErrTunnelAttached = errors.New("p2p: tunnel already attached")
	// ErrPeerUnreachable reports that the tunnel's peer end could not be
	// opened; the cause is wrapped, so errors.Is/errors.As still match it.
	ErrPeerUnreachable = errors.New("p2p: peer unreachable")
	// ErrForward reports a failed static forward registration: a configuration
	// error (bad listen address, no relay configured, port in use), not a
	// transient one. A caller that serves through an unreachable relay must
	// still fail on this; errors.Is is the test. The cause is wrapped.
	ErrForward = errors.New("p2p: forward")
)
