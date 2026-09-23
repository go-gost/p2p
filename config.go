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
