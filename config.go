package p2p

import "time"

// Config is the endpoint configuration: everything the host reads to build its
// identity, its relay engine and its data planes. The yaml tags are the
// config-file schema, but the file itself is read by the binary that deploys
// the library (cmd/p2p), not by this package.
type Config struct {
	Derp string `yaml:"derp,omitempty"`
	// Transport selects the data plane for every peer: "" or "kcp" keeps the
	// existing secure+KCP+smux path, "quic" opts into the QUIC data plane. The
	// mode is global (one data plane per endpoint) and read once at startup; a
	// running endpoint never switches. QUIC is strict: a peer that cannot speak
	// it is unreachable rather than served over KCP, and QUIC requires relay
	// (DERP) mode.
	Transport string `yaml:"transport,omitempty"`
	// Key is the endpoint identity, in one of two forms: a 64-character
	// hex-encoded curve25519 private key held in memory, or a path to an
	// existing key file. p2p only reads the file and never creates or writes
	// one; the caller owns persistence (see GenerateKey). A 64-hex value is
	// always treated as key material, so prefix a file path that looks like one
	// with "./". Relay mode needs a key; stub mode does not.
	Key string `yaml:"key,omitempty"`
	// Target is the default forwarding target for inbound connections.
	Target  string   `yaml:"target,omitempty"`
	Targets []string `yaml:"targets,omitempty"`
	Stun    string   `yaml:"stun,omitempty"`
	Direct  *bool    `yaml:"direct,omitempty"`
	// IPv6 enables the IPv6 direct-path family: the egress probe, the v6
	// candidate collection and the v6 capability bit. Off by default, so a host
	// never looks for, advertises or dials an IPv6 path unless its operator
	// asked for one.
	IPv6     bool            `yaml:"ipv6,omitempty"`
	TLS      *TLSConfig      `yaml:"tls,omitempty"`
	Timeouts *TimeoutsConfig `yaml:"timeouts,omitempty"`
	// QUIC tunes the QUIC data plane. It is ignored when Transport is kcp.
	QUIC     *QUICConfig     `yaml:"quic,omitempty"`
	Forwards []ForwardConfig `yaml:"forwards,omitempty"`
	// Faults injects deliberate transport failures (debug only — see
	// FaultsConfig). Nil or zero means nothing is injected.
	Faults *FaultsConfig `yaml:"faults,omitempty"`
}

// FaultsConfig deliberately breaks the transport to reproduce a field failure
// locally: each knob makes the engine drop frames it would otherwise send or
// deliver. Every knob is off in the zero value, and a process that enables one
// says so loudly at startup.
//
// This is a debugging tool, not a feature. An injected drop is indistinguishable
// from a real one at every layer above, which is the point — and why it must
// never be enabled in a deployment that matters. It is config-file only: there
// is no RPC, no env var and no flag, so a running host cannot be told to break
// itself over the network.
type FaultsConfig struct {
	// DropCtrl drops every control-plane frame on the relay path: the candidate
	// exchange, ctrlCaps, and the ctrlSecure half. Encryption is forced and
	// negotiates on that same channel, so with this on nothing settles — the
	// punch and the session itself alike, which is what a peer that cannot
	// negotiate looks like from here.
	DropCtrl bool `yaml:"dropCtrl" json:"dropCtrl"`
	// DropData drops every data frame — tunnel payload and the smux keepalive
	// NOP alike — on both the relay and the direct path, in both directions.
	DropData bool `yaml:"dropData" json:"dropData"`
	// DropDirect drops data on the direct underlay only, in both directions,
	// while the relay path keeps working. It is the per-path mute: it forces
	// "direct dies, relay recovers" so a test can watch the pair fall back
	// without breaking the relay. Like the other faults it is built from the
	// config at startup and never changes at runtime.
	DropDirect bool `yaml:"dropDirect" json:"dropDirect"`
	// DropPong swallows the relay's pong replies: our own answer to the relay's
	// ping and the stamp that feeds the relay-silence watchdog, so a live relay
	// reads as a dead one.
	DropPong bool `yaml:"dropPong" json:"dropPong"`
	// DropDataRate drops one in every round(1/rate) relay data frames on the
	// relay send path, deterministically. This is the loss injector used to
	// exercise KCP retransmission: dropped segments must be repaired by the
	// underlay rather than desyncing the record framing above it. Zero disables
	// the injector.
	DropDataRate float64 `yaml:"dropDataRate" json:"dropDataRate"`
	// Silence stops sending *anything* to the peer for SilenceFor, every
	// SilenceEvery, while SilenceEvery > 0. This is the measured field failure:
	// the session's peer-side frames stop arriving without the path dying, and
	// the direct session lives or dies by its keepalive timeout (a timeout
	// shorter than SilenceFor tears it down; the shipped 15s survives). The
	// window opens when the process does.
	SilenceFor   time.Duration `yaml:"silenceFor" json:"silenceFor"`
	SilenceEvery time.Duration `yaml:"silenceEvery" json:"silenceEvery"`
}

// TimeoutsConfig tunes deployment-dependent timings. Zero values keep the
// built-in defaults; internal mechanism timeouts stay hardcoded.
//
// The timings are process-wide: they are applied when an endpoint is created
// and a later endpoint inherits the values already applied. A process may run
// several endpoints (for example one per relay, sharing one identity); they
// must give identical timeouts (or none).
type TimeoutsConfig struct {
	PunchWait     time.Duration `yaml:"punchWait,omitempty"`
	Punch         time.Duration `yaml:"punch,omitempty"`
	Seed          time.Duration `yaml:"seed,omitempty"`
	Backoff       time.Duration `yaml:"backoff,omitempty"`
	DerpKeepAlive time.Duration `yaml:"derpKeepAlive,omitempty"`
	Smux          *SmuxTimeouts `yaml:"smux,omitempty"`
	// DirectSmux is retained for config compatibility: the direct (hole-punched)
	// plane no longer runs its own smux session, so these values are accepted
	// for compatibility but no longer affect any session. The direct path rides
	// the pair's session and has its own underlay idle watchdog.
	DirectSmux *SmuxTimeouts `yaml:"directSmux,omitempty"`
}

// SmuxTimeouts tunes a smux keepalive: the pair's session under "smux".
// "directSmux" is a compatibility no-op. Timeout must be >= 2x Interval
// (validated when the endpoint is created).
type SmuxTimeouts struct {
	Interval time.Duration `yaml:"interval,omitempty"`
	Timeout  time.Duration `yaml:"timeout,omitempty"`
}

// QUICConfig tunes the QUIC data plane. The settings are host-wide (they apply
// to every peer of the endpoint) and read at startup; the block is ignored when
// Transport is kcp. Zero values keep the built-in defaults: 1200 bytes, 32 KiB,
// 200µs, 5s, 15s and 10s respectively (see resolveQUICSettings).
//
// Validation: mtu >= 1200, relayBatchBytes <= 64 KiB, idle > keepAlive, and
// handshakeTimeout > 0.
type QUICConfig struct {
	// MTU is the fixed QUIC packet size. 1200 is the conservative default so a
	// relay packet and a direct-path UDP datagram fit the same path.
	MTU int `yaml:"mtu,omitempty"`
	// RelayBatchBytes is the most relay payload bytes one DERP frame carries.
	RelayBatchBytes int `yaml:"relayBatchBytes,omitempty"`
	// RelayFlush is the longest a relay batch waits before it is sent.
	RelayFlush time.Duration `yaml:"relayFlush,omitempty"`
	// KeepAlive is the QUIC keepalive period.
	KeepAlive time.Duration `yaml:"keepAlive,omitempty"`
	// Idle is the QUIC maximum idle timeout; it must exceed KeepAlive.
	Idle time.Duration `yaml:"idle,omitempty"`
	// HandshakeTimeout bounds QUIC connection establishment, including the
	// relay handshake window.
	HandshakeTimeout time.Duration `yaml:"handshakeTimeout,omitempty"`
}

// TLSConfig mirrors the --tls.* flags. Secure is a pointer so an omitted
// "secure" (default true) is distinguishable from an explicit "secure: false".
type TLSConfig struct {
	Secure *bool  `yaml:"secure,omitempty"`
	CAFile string `yaml:"caFile,omitempty"`
}

// ForwardConfig is a pre-configured static port forward: bind Listen and bridge
// accepted connections to the peer's public key.
type ForwardConfig struct {
	Listen string `yaml:"listen,omitempty"`
	Peer   string `yaml:"peer,omitempty"`
}

// TargetList merges the legacy scalar `target` with the `targets` list, scalar
// first, into the raw spec list the engine parses.
func (c *Config) TargetList() []string {
	specs := make([]string, 0, len(c.Targets)+1)
	if c.Target != "" {
		specs = append(specs, c.Target)
	}
	specs = append(specs, c.Targets...)
	return specs
}
