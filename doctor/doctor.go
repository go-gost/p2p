// Package doctor renders one pasteable p2p diagnostic report: a point-in-time
// snapshot of an endpoint's transports and peers, plus verdicts — the
// "raise the log level and send me the log" replacement.
//
// It is a pure formatter over p2p.Status and the local context an endpoint does
// not carry (its identity, its relay/STUN settings). Two callers share it: the
// `p2p doctor` CLI (over the gRPC control plane) and wisper (in-process, so it
// also sees the relay's liveness). The package depends on nothing but the
// contract package and the standard library.
package doctor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-gost/p2p"
)

// Options is the local, non-Status context the report names: who is asking
// (Version, Host, Identity), the deployment it is pointed at (RelayURL, STUN,
// Direct), and the peer to narrow to (Peer). Every field is optional; an empty
// one simply drops or degrades the line it names.
type Options struct {
	// Version names the build in the header.
	Version string
	// Host is the control plane the report was read from, when it was read over
	// one. Empty (an in-process caller) drops the line.
	Host string
	// Identity is the local public key, or, for a caller that could not resolve
	// it, a human-readable reason. Empty prints "(unresolved)".
	Identity string
	// RelayURL is the DERP relay the endpoint is configured with.
	RelayURL string
	// STUN is the STUN server the direct path would use (empty = not
	// configured).
	STUN string
	// Direct is the direct-path toggle; nil when the caller does not know it.
	Direct *bool
	// Peer, when set, narrows the peer section and its verdict to that one key.
	Peer string
	// InProcess marks a caller that reads the Status in process (wisper), where
	// a zero field means the measurement genuinely has not happened yet. A
	// wire-sourced caller (the p2p doctor CLI, over a proto that is frozen)
	// leaves it false: a field the control plane does not carry is structurally
	// zero there, so the report says it was not reported rather than asserting
	// a zero. False is the safe default — the shape a new caller gets unless it
	// knows the Status came from the live endpoint.
	InProcess bool
}

// Report renders st as a plain-text diagnostic report with verdicts.
func Report(st p2p.Status, opts Options) string {
	var b strings.Builder

	if opts.Version != "" {
		fmt.Fprintf(&b, "p2p doctor %s\n", opts.Version)
	} else {
		b.WriteString("p2p doctor\n")
	}
	if opts.Host != "" {
		field(&b, "host", opts.Host)
	}
	field(&b, "local key", identity(opts.Identity))
	field(&b, "relay", orNone(opts.RelayURL))
	if state, known := relayState(st); known {
		field(&b, "relay state", state)
	} else {
		field(&b, "relay state", "not reported by the control plane")
	}
	// The relay's own round trip: the one latency here measured by this host
	// instead of inferred from a peer's session, and the only thing that tells
	// "the relay is slow" from "the relay is down" while a direct session keeps
	// every counter healthy. A zero has two different causes — not measured yet
	// (an in-process caller) and not carried over the wire (a frozen proto) —
	// and the formatter names which one applies, so the CLI cannot assert a
	// host that has answered pings for days never measured one.
	if st.RelayConnected {
		field(&b, "relay rtt", relayRTT(st, opts))
	}
	if opts.Direct != nil {
		field(&b, "direct path", onOff(*opts.Direct))
	}
	// The direct path the host is actually running with. The "direct path" line
	// above is the caller's own configuration, which can disagree with it: an
	// embedder that probed STUN and got no answer hands p2p an empty server, so
	// a host configured for direct runs relay-only and says nothing about why.
	if c := st.DirectConfig; c != (p2p.DirectConfig{}) {
		stun := orNone(c.Stun)
		switch {
		case c.Stun == "":
			// nothing to probe with
		case c.StunFailed:
			stun += " (does not answer)"
		default:
			stun += " (answered)"
		}
		ipv6 := "off"
		switch {
		case c.IPv6Enabled && c.IPv6:
			ipv6 = "on"
		case c.IPv6Enabled:
			ipv6 = "on (no egress)"
		}
		field(&b, "direct config", fmt.Sprintf("on=%v, stun=%s, ipv6=%s",
			c.Direct, stun, ipv6))
		if c.Reason != "" {
			field(&b, "direct reason", c.Reason)
		}
	}

	b.WriteString("\nsummary:\n")
	field(&b, "  tunnels", fmt.Sprintf("%d", st.Tunnels))
	field(&b, "  direct peers", fmt.Sprintf("%d", st.DirectPeers))
	field(&b, "  relay peers", fmt.Sprintf("%d", st.DerpPeers))
	field(&b, "  punches", fmt.Sprintf("%d attempts, %d success", st.PunchAttempts, st.PunchSuccess))
	field(&b, "  streams", fmt.Sprintf("%d direct, %d relay", st.StreamsDirect, st.StreamsDerp))
	field(&b, "  encryption", fmt.Sprintf("%d encrypted, %d plaintext (encryption is forced)",
		st.EncryptedPeers, st.PlaintextPeers))

	b.WriteString("\npeers:\n")
	keys := peerKeys(st, opts.Peer)
	if len(keys) == 0 {
		if opts.Peer != "" {
			field(&b, "  "+opts.Peer, "not connected")
		} else {
			b.WriteString("  (none connected)\n")
		}
	}
	for _, k := range keys {
		peerBlock(&b, k, st.PeerDiagnostics[k])
	}

	b.WriteString("\nverdicts:\n")
	for _, v := range verdicts(st, opts) {
		b.WriteString("  " + v + "\n")
	}
	return b.String()
}

// identity is the local key line: the key, or why it did not resolve.
func identity(s string) string {
	if s == "" {
		return "(unresolved)"
	}
	return s
}

// onOff renders a toggle.
func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// field writes one "label  value" line, the label padded so a pasted report
// lines up.
func field(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "%-16s %s\n", label+":", value)
}

// underlayWord reports both underlays as themselves, so an underlay that is
// answering a heartbeat is distinguishable from one that is carrying bytes.
//
// The heartbeat is a raw-UDP magic packet: it round-trips on the socket and is
// consumed before KCP ever sees it, so "hb alive" is a statement about the NAT
// path and nothing else. The recency ages are the per-underlay datagram
// stamps, which bytes do move — except that "last direct recv" is re-armed by a
// heartbeat answer too, so a reader must compare it against the session and
// data-plane lines above before reading the path as healthy.
func underlayWord(d p2p.PeerDiagnostic) string {
	k := d.RelayKCP
	return fmt.Sprintf("direct hb %s, direct last recv %s, relay last recv %s",
		hbWord(k.DirectAlive), recvWord(k.DirectLastRecvAge), recvWord(k.RelayLastRecvAge))
}

// hbWord names a heartbeat answer, or "unknown" when nothing was measured.
func hbWord(alive bool) string {
	if alive {
		return "alive"
	}
	return "unknown"
}

// recvWord renders a per-underlay silence age. 0 means no stamp at all — the
// underlay never delivered a datagram — which is a different fact from "silent
// for 0s", and negative values (a relay-only peer with no direct stamp) mean the
// same thing.
func recvWord(d time.Duration) string {
	if d <= 0 {
		return "never"
	}
	return d.String()
}

// peerBlock writes one peer's full diagnostic, its trace one round per line.
func peerBlock(b *strings.Builder, key string, d p2p.PeerDiagnostic) {
	fmt.Fprintf(b, "  %s\n", key)
	field(b, "    path", orNone(d.Path))
	field(b, "    reason", orNone(d.Reason))
	field(b, "    state", orNone(d.State))
	field(b, "    failed", fmt.Sprintf("%t", d.Failed))
	field(b, "    last error", orNone(d.LastError))
	// Session churn, and only when it happened: a healthy pair's zeros are noise,
	// but a pair rebuilding every few seconds is the thing being hunted for and
	// used to be visible only by grepping the log.
	if d.RelayRebuilds > 0 || d.PeerRekeys > 0 {
		field(b, "    relay churn", fmt.Sprintf("%d rebuilds, %d peer rekeys",
			d.RelayRebuilds, d.PeerRekeys))
	}
	// The pair's relay KCP health: what kcp-go exposes per session
	// (SRTT/RTO/RTTVar), the configured MTU/window, and the pair's own datagram
	// byte counters. Shown only when a session exists (a direct-only peer has
	// none), so zeros never read as a healthy idle session.
	if d.RelayKCP.Live {
		field(b, "    relay kcp", fmt.Sprintf("srtt=%dms rto=%dms rttvar=%dms conv=%d mtu=%d sndwnd=%d rcvwnd=%d sent=%dB rcvd=%dB",
			d.RelayKCP.SRTT, d.RelayKCP.RTO, d.RelayKCP.RTTVar, d.RelayKCP.Conv,
			d.RelayKCP.Mtu, d.RelayKCP.SndWnd, d.RelayKCP.RcvWnd,
			d.RelayKCP.BytesSent, d.RelayKCP.BytesRcvd))
	}
	field(b, "    peer addr", orNone(d.PeerAddr))
	// The two facts get their own labels: the endpoint one is about the
	// peer's address translation, the one-way one is about the path's health
	// and is not a NAT conclusion.
	endpointFact, oneWayFact := natFacts(d)
	if endpointFact != "" {
		field(b, "    nat shape", "peer-endpoint-differs ("+endpointFact+")")
	}
	if oneWayFact != "" {
		field(b, "    path health", "one-way ("+oneWayFact+")")
	}
	field(b, "    candidates", fmt.Sprintf("%d", d.Candidates))
	field(b, "    caps", orNone(strings.Join(d.Caps, ", ")))
	// The three layers, each attributed separately. They used to be one word:
	// "path" and "state" come from the punch machine and from underlay recency,
	// and "last traffic" carried a note telling the reader to discount it, so a
	// dead data plane under a heartbeat-alive underlay printed as healthy and
	// stayed that way for 45 minutes. Neither path nor state reads the session
	// object, which is why "session" now has a line of its own.
	field(b, "    session", orNone(d.SessionState))
	field(b, "    underlay", underlayWord(d))
	// "last traffic", not "last frame": smux keepalive NOPs never reach the
	// pump, so an idle peer ages here and "last recv" reads like a dead path.
	// The window is stated next to the number for the same reason — but it is no
	// longer the only field that could contradict path/state, so it is no longer
	// the only one a reader has to be told to distrust.
	field(b, "    last traffic", fmt.Sprintf("%s (a connected idle peer ages here: keepalives carry no traffic)",
		d.LastRecvAge))
	field(b, "    session age", d.SessionAge.String())
	field(b, "    punch", fmt.Sprintf("%d attempts, %d ups, %d drops", d.Attempts, d.Ups, d.Drops))
	if len(d.Trace) > 0 {
		b.WriteString("    trace:\n")
		for _, line := range d.Trace {
			b.WriteString("      " + line + "\n")
		}
	} else {
		field(b, "    trace", "(none)")
	}
}

// verdicts are the derived one-liners — the value over a raw dump: the relay's
// state (reported or inferred), encryption coverage, STUN, and why each peer
// sits where it does.
func verdicts(st p2p.Status, opts Options) []string {
	out := []string{relayVerdict(st)}

	connected := st.DirectPeers + st.DerpPeers
	switch {
	case connected == 0:
		out = append(out, "encryption: no connected peers")
	case st.EncryptedPeers >= connected:
		out = append(out, "encryption: every connected peer")
	default:
		out = append(out, fmt.Sprintf("encryption: %d of %d connected peers encrypted", st.EncryptedPeers, connected))
	}

	out = append(out, stunVerdict(st, opts))
	if opts.Peer != "" {
		if _, ok := st.PeerDiagnostics[opts.Peer]; !ok {
			out = append(out, "peer "+opts.Peer+": not connected")
		}
	}
	for _, k := range peerKeys(st, opts.Peer) {
		d := st.PeerDiagnostics[k]
		line := peerVerdict(k, d)
		// The shape's evidence rides with the verdict: what was observed, in
		// the reader's terms, so the one-liner says why the peer is where it
		// is and not just where.
		endpointFact, oneWayFact := natFacts(d)
		var facts []string
		if endpointFact != "" {
			facts = append(facts, endpointFact)
		}
		if oneWayFact != "" {
			facts = append(facts, oneWayFact)
		}
		if len(facts) > 0 {
			line += "; " + strings.Join(facts, "; ")
		}
		out = append(out, line)
	}
	if v := natShapeVerdict(st, opts); v != "" {
		out = append(out, v)
	}
	out = append(out, peerDownPairingRule())
	return out
}

// natHasEndpointFact reports whether a shape verdict carries the endpoint
// fact — the one that is about the peer's address translation. The verdict
// word is a closed vocabulary, so it is matched exactly.
func natHasEndpointFact(shape string) bool {
	switch shape {
	case "peer-endpoint-differs", "one-way+peer-endpoint-differs":
		return true
	default:
		return false
	}
}

// natFacts splits a peer's shape verdict into the facts it carries, each
// with its evidence. An empty result means the verdict carries none of them
// (or is a word this doctor does not know).
//
// The two facts are kept apart on purpose. "The peer answers from an endpoint
// it did not announce" is about its address translation; "the direct path has
// been one-way" is about the path's health, and a one-way path is not a NAT
// conclusion — so it is never filed under a NAT label, here or in the peer
// block.
//
// The verdict word is a closed vocabulary owned by the engine, so it is
// matched exactly: a word this doctor does not know yields no facts rather
// than being half-parsed into the wrong one.
func natFacts(d p2p.PeerDiagnostic) (endpointFact, oneWayFact string) {
	switch d.NATShape {
	case "peer-endpoint-differs", "one-way+peer-endpoint-differs":
		endpointFact = fmt.Sprintf(
			"peer answers from %s, an endpoint it did not announce; its mapping varies by destination or changed, observed %s ago",
			orNone(d.PeerAddr), d.NATObservedAge)
	}
	switch d.NATShape {
	case "one-way", "one-way+peer-endpoint-differs":
		if d.OneWayAge > 0 {
			// The episode is over: the path was retired, or the shape stopped
			// on a live path. The age dates it either way.
			oneWayFact = fmt.Sprintf(
				"the direct path was one-way for %s, %s ago; we sent and nothing came back",
				d.OneWayFor, d.OneWayAge)
		} else {
			oneWayFact = fmt.Sprintf(
				"the direct path has been one-way for %s; we send and nothing comes back", d.OneWayFor)
		}
	}
	return endpointFact, oneWayFact
}

// natShapeVerdict is the host-level line about the pairs' address
// translation: how many of the peers that were observed answer from an
// endpoint they did not announce.
//
// A wire-sourced report says the control plane does not carry the shape
// rather than let a zero read as "nothing was observed" — the same discipline
// the relay state and the relay RTT follow. The line is omitted when no peer
// shows the fact: a one-way path is a path's health, not a translator's
// shape, and it is reported per peer.
func natShapeVerdict(st p2p.Status, opts Options) string {
	if !opts.InProcess {
		return "NAT shape: not reported by the control plane"
	}
	observed, differs := 0, 0
	for _, k := range peerKeys(st, opts.Peer) {
		d := st.PeerDiagnostics[k]
		if d.NATObservedAge <= 0 {
			continue // never observed: nothing was checked
		}
		observed++
		if natHasEndpointFact(d.NATShape) {
			differs++
		}
	}
	if differs == 0 {
		return ""
	}
	return fmt.Sprintf("NAT shape: %d of %d observed peers answer from an endpoint they did not announce",
		differs, observed)
}

// peerDownPairingRule is how to read the relay-session down/up lines, carried
// in the report because it is the thing a reader needs and cannot infer from
// the numbers here: the rebuild line is log-only, so nothing in this report
// shows a down or an up.
//
// It is last on purpose — it is a footnote to the verdicts above it, not a
// verdict about this host. Without it "a rebuild with no kill in the log" reads
// as a missing event, and gets "fixed" by someone adding a kill line to the
// silent keepalive path.
func peerDownPairingRule() string {
	return `peer down/up (in the log): one outage = one "relay session rebuilt" line; ` +
		`empty relayReason means the smux keepalive judged the peer dead with no kill, ` +
		`so a rebuild without a kill is normal, while a kill without a rebuild means the outage never healed; ` +
		`a "relay-silent" kill is the idle watchdog's strike 1 (pair silent past its window, mux only, keys kept), ` +
		`and a "link-lost" right after it is strike 2 resetting the pair — one outage in two lines, not two outages`
}

// relayVerdict names the relay's state. A caller that carries it (in-process,
// or the gRPC reply since the relay fields were added to the proto) gets it
// directly; otherwise it is inferred from the peers the host serves — a peer on
// the relay path could only be there over a live relay.
func relayVerdict(st p2p.Status) string {
	if state, known := relayState(st); known {
		return "relay: " + state
	}
	for _, k := range sortedKeys(st.PeerDiagnostics) {
		if st.PeerDiagnostics[k].Path == "derp" {
			return "relay: connected (peer " + k + " is served over it)"
		}
	}
	return "relay: unknown (not reported by the control plane)"
}

// stunVerdict names STUN's state: a peer reason or path of stun-unreachable
// means STUN is configured but silent; otherwise it is named or absent.
func stunVerdict(st p2p.Status, opts Options) string {
	for _, k := range sortedKeys(st.PeerDiagnostics) {
		d := st.PeerDiagnostics[k]
		if d.Reason == "stun-unreachable" || d.Path == "stun-unreachable" {
			return "STUN " + orNone(opts.STUN) + ": UNREACHABLE (no answer; the direct path falls back to the relay)"
		}
	}
	if opts.STUN == "" {
		return "STUN: not configured (the IPv4 direct path is off; IPv6 is independent)"
	}
	return "STUN " + opts.STUN + ": configured"
}

// peerVerdict is one peer's one-liner: where it is and why.
func peerVerdict(key string, d p2p.PeerDiagnostic) string {
	switch d.Path {
	case "direct":
		// The underlay and the punch say direct; only the session says whether
		// anything is being carried. A verdict built from the first two alone
		// read "up" over a one-way-dead data plane, which is the report shape
		// that hid a 45-minute outage from the one person watching it.
		if d.SessionState == "down" {
			return fmt.Sprintf("peer %s: direct underlay up but the session is DOWN (underlay %s, last traffic %s) — the path is not carrying",
				key, underlayWord(d), d.LastRecvAge)
		}
		return fmt.Sprintf("peer %s: direct path up (session %s, last traffic %s)", key, d.SessionAge, d.LastRecvAge)
	case "punching":
		return fmt.Sprintf("peer %s: punch in flight (candidates %d)", key, d.Candidates)
	case "failed":
		detail := "punch failed"
		if d.LastError != "" {
			detail = "punch failed (" + d.LastError + ")"
		}
		return fmt.Sprintf("peer %s: on the relay; %s — candidates %d", key, detail, d.Candidates)
	case "disabled":
		return fmt.Sprintf("peer %s: on the relay; direct path disabled", key)
	case "peer-direct-off":
		return fmt.Sprintf("peer %s: on the relay; the peer has its direct path off", key)
	case "no-candidates":
		return fmt.Sprintf("peer %s: on the relay; no candidates (no STUN and no IPv6 egress)", key)
	case "stun-unreachable":
		return fmt.Sprintf("peer %s: on the relay; STUN unreachable", key)
	case "":
		return fmt.Sprintf("peer %s: no transport reported", key)
	default:
		return fmt.Sprintf("peer %s: on the relay (%s)", key, d.Path)
	}
}

// relayRTT formats the relay's own round trip: milliseconds once the relay
// has answered a ping, else the reason there is no number to show — which is
// the caller's, not the field's. An in-process caller that reads zero has a
// relay that has not answered a ping yet; a wire-sourced caller reads zero
// always, because the control-plane proto does not carry the field, and must
// say it was not reported rather than claim a measurement that never ran.
func relayRTT(st p2p.Status, opts Options) string {
	if st.RelayRTT > 0 {
		return fmt.Sprintf("%dms", st.RelayRTT)
	}
	if !opts.InProcess {
		return "not reported by the control plane"
	}
	return "not measured yet"
}

// relayState reports the relay's liveness when the Status carried it
// (in-process, or over gRPC once the proto carries the relay fields).
func relayState(st p2p.Status) (string, bool) {
	switch {
	case st.RelayConnected:
		return "connected", true
	case st.RelayError != "":
		return "UNREACHABLE (" + st.RelayError + ")", true
	}
	return "", false
}

// peerKeys is the peers to render, sorted: one when peer is set and connected,
// none when it is set and absent, all otherwise.
func peerKeys(st p2p.Status, peer string) []string {
	if peer != "" {
		if _, ok := st.PeerDiagnostics[peer]; ok {
			return []string{peer}
		}
		return nil
	}
	return sortedKeys(st.PeerDiagnostics)
}

func sortedKeys(m map[string]p2p.PeerDiagnostic) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
