package host

// The pair's NAT shape: what the punch observed about the two ends' address
// translation, in one word.
//
// The two facts are independent and the combination is a verdict of its own:
//
//   - "peer-endpoint-differs" — the peer answered the seed from an endpoint it
//     never announced. Its mapping varies by destination (a per-destination
//     NAT) or changed since its own STUN probe. It does NOT mean the peer is
//     unreachable: the punch uses the endpoint that answered (the learned
//     address), so this shape is dialled successfully. It matters because the
//     candidate a peer announces is not always the endpoint to reach it at,
//     and a reader has to know that when a punch takes extra rounds.
//   - "one-way" — the direct path is sending while receiving nothing. This is
//     a PATH HEALTH fact, not a NAT shape: the common cause is a half-dead
//     session (the bytes under the relay are fine, the session is not), and
//     the e2e suite injects the shape on purpose. It is reported beside the
//     peer-endpoint fact rather than folded into it.
//
// The verdict is diagnostic only: it says what was observed, and nothing
// decides whether to punch.

// natShape is the pair's NAT-shape verdict. oneWay says the direct path was
// seen one-way — an event that may still be running or may have ended; the
// report dates it.
func natShape(differs bool, oneWay bool) string {
	switch {
	case differs && oneWay:
		return "one-way+peer-endpoint-differs"
	case differs:
		return "peer-endpoint-differs"
	case oneWay:
		return "one-way"
	default:
		return ""
	}
}
