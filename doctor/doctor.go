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
		field(&b, "direct config", fmt.Sprintf("on=%v, stun=%s, ipv6=%v",
			c.Direct, stun, c.IPv6))
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
	field(b, "    candidates", fmt.Sprintf("%d", d.Candidates))
	field(b, "    caps", orNone(strings.Join(d.Caps, ", ")))
	field(b, "    session age", d.SessionAge.String())
	// "last traffic", not "last frame": smux keepalive NOPs never reach the
	// pump, so an idle peer ages here and "last recv" reads like a dead path.
	// The window is stated next to the number for the same reason.
	field(b, "    last traffic", fmt.Sprintf("%s (a connected idle peer ages here: keepalives carry no traffic)",
		d.LastRecvAge))
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
		out = append(out, peerVerdict(k, st.PeerDiagnostics[k]))
	}
	out = append(out, peerDownPairingRule())
	return out
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
