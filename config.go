package p2p

import "time"

// Config is the endpoint configuration: everything the host reads to build its
// identity, its relay engine and its data planes. The yaml tags are the
// config-file schema, but the file itself is read by the binary that deploys
// the library (cmd/p2p), not by this package.
type Config struct {
	Derp     string          `yaml:"derp,omitempty"`
	Key      string          `yaml:"key,omitempty"`
	KeyHex   string          `yaml:"keyHex,omitempty"`
	Target   string          `yaml:"target,omitempty"`
	Targets  []string        `yaml:"targets,omitempty"`
	Stun     string          `yaml:"stun,omitempty"`
	Direct   *bool           `yaml:"direct,omitempty"`
	TLS      *TLSConfig      `yaml:"tls,omitempty"`
	Timeouts *TimeoutsConfig `yaml:"timeouts,omitempty"`
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
// and a later endpoint inherits the values already applied. One endpoint per
// process is the model; a process that builds two must give them identical
// timeouts (or none).
type TimeoutsConfig struct {
	PunchWait     time.Duration `yaml:"punchWait,omitempty"`
	Punch         time.Duration `yaml:"punch,omitempty"`
	Seed          time.Duration `yaml:"seed,omitempty"`
	Backoff       time.Duration `yaml:"backoff,omitempty"`
	DerpKeepAlive time.Duration `yaml:"derpKeepAlive,omitempty"`
	Smux          *SmuxTimeouts `yaml:"smux,omitempty"`
	// DirectSmux tunes the direct (hole-punched) session's keepalive, which runs
	// tighter than the relay's by default. It is negotiated: smux answers a NOP
	// with nothing, so a session is kept alive by the frames the peer sends, and
	// a timeout shorter than the peer's ping interval would tear the session
	// down on a loop. Both ends advertise the pair (ctrlCaps) and a peer that
	// does not gets the relay's, so the tighter values apply only when both
	// sides run this version. Until a dead session is noticed it is served as
	// live — the peer reads as "direct" and a new stream goes to the dead path
	// instead of the relay. Widen it for slow or lossy direct paths.
	DirectSmux *SmuxTimeouts `yaml:"directSmux,omitempty"`
}

// SmuxTimeouts tunes a smux keepalive: the relay session's under "smux", the
// direct session's under "directSmux". Timeout must be >= 2x Interval
// (validated when the endpoint is created).
type SmuxTimeouts struct {
	Interval time.Duration `yaml:"interval,omitempty"`
	Timeout  time.Duration `yaml:"timeout,omitempty"`
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
