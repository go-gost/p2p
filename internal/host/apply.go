package host

import (
	"fmt"
	"time"

	"github.com/go-gost/p2p"
)

// applyDefaults fills in place the Config defaults the library owns, so a host
// behaves identically whether cfg came from a YAML file, flags, or a caller.
// It mutates the caller's *p2p.Config (TLS, Direct).
func applyDefaults(cfg *p2p.Config) {
	if cfg.TLS == nil {
		cfg.TLS = &p2p.TLSConfig{}
	}
	if cfg.TLS.Secure == nil {
		def := true
		cfg.TLS.Secure = &def
	}
	if cfg.Direct == nil {
		def := true
		cfg.Direct = &def
	}
}

// transportMode is the data plane an endpoint selected for every peer. It is
// fixed when the Host is built; see p2p.Config.Transport.
type transportMode uint8

const (
	transportKCP transportMode = iota
	transportQUIC
)

// QUIC data-plane defaults. The values are host-wide and overridable through
// p2p.QUICConfig; they mirror the design's stable, conservative choices.
const (
	defaultQUICMTU              = 1200
	defaultQUICRelayBatchBytes  = 32 << 10
	defaultQUICRelayFlush       = 200 * time.Microsecond
	defaultQUICKeepAlive        = 5 * time.Second
	defaultQUICIdle             = 15 * time.Second
	defaultQUICHandshakeTimeout = 10 * time.Second

	minQUICMTU             = 1200
	maxQUICRelayBatchBytes = 64 << 10
)

// quicSettings is the resolved, validated form of p2p.QUICConfig. Unlike the
// config, every field holds its effective value.
type quicSettings struct {
	MTU              int
	RelayBatchBytes  int
	RelayFlush       time.Duration
	KeepAlive        time.Duration
	Idle             time.Duration
	HandshakeTimeout time.Duration
}

// resolveTransport maps Config.Transport to the data plane mode. Empty and
// "kcp" mean the existing KCP path; "quic" is strict opt-in. Anything else is
// rejected so a typo cannot silently leave an endpoint on KCP.
func resolveTransport(cfg *p2p.Config) (transportMode, error) {
	switch cfg.Transport {
	case "", "kcp":
		return transportKCP, nil
	case "quic":
		return transportQUIC, nil
	default:
		return transportKCP, fmt.Errorf("transport: unknown mode %q (want kcp or quic)", cfg.Transport)
	}
}

// resolveQUICSettings merges the quic block over the built-in defaults and
// validates the result. Nil or a zero field keeps the default.
func resolveQUICSettings(c *p2p.QUICConfig) (quicSettings, error) {
	s := quicSettings{
		MTU:              defaultQUICMTU,
		RelayBatchBytes:  defaultQUICRelayBatchBytes,
		RelayFlush:       defaultQUICRelayFlush,
		KeepAlive:        defaultQUICKeepAlive,
		Idle:             defaultQUICIdle,
		HandshakeTimeout: defaultQUICHandshakeTimeout,
	}
	if c != nil {
		if c.MTU != 0 {
			s.MTU = c.MTU
		}
		if c.RelayBatchBytes != 0 {
			s.RelayBatchBytes = c.RelayBatchBytes
		}
		if c.RelayFlush != 0 {
			s.RelayFlush = c.RelayFlush
		}
		if c.KeepAlive != 0 {
			s.KeepAlive = c.KeepAlive
		}
		if c.Idle != 0 {
			s.Idle = c.Idle
		}
		if c.HandshakeTimeout != 0 {
			s.HandshakeTimeout = c.HandshakeTimeout
		}
	}

	if s.MTU < minQUICMTU {
		return quicSettings{}, fmt.Errorf("quic.mtu %d must be >= %d", s.MTU, minQUICMTU)
	}
	if s.RelayBatchBytes <= 0 || s.RelayBatchBytes > maxQUICRelayBatchBytes {
		return quicSettings{}, fmt.Errorf("quic.relayBatchBytes %d must be in (0, %d]", s.RelayBatchBytes, maxQUICRelayBatchBytes)
	}
	if s.RelayFlush < 0 {
		return quicSettings{}, fmt.Errorf("quic.relayFlush must be positive")
	}
	if s.KeepAlive < 0 {
		return quicSettings{}, fmt.Errorf("quic.keepAlive must be positive")
	}
	if s.Idle <= s.KeepAlive {
		return quicSettings{}, fmt.Errorf("quic.idle (%s) must exceed quic.keepAlive (%s)", s.Idle, s.KeepAlive)
	}
	if s.HandshakeTimeout <= 0 {
		return quicSettings{}, fmt.Errorf("quic.handshakeTimeout must be positive")
	}
	return s, nil
}

// applyTimeouts validates and applies the timeouts config to the package-level
// timing vars. Zero values keep defaults; invalid values are rejected at
// startup so a misconfiguration fails loudly instead of producing a silently
// broken punch. smux timeout must be >= 2x the interval: smux's own
// VerifyConfig only requires >=, and the failing case hit twice was equality
// (an idle session kills itself after ~interval).
//
// The timings are process-wide, not per-Host: a second New merges its non-zero
// values into those already applied, so a Host with zero timeouts inherits the
// first Host's. A process may run several Hosts, but they must share one
// timeouts configuration (see p2p.TimeoutsConfig).
func applyTimeouts(t *p2p.TimeoutsConfig) error {
	if t == nil {
		return nil
	}
	for _, v := range []struct {
		name string
		val  time.Duration
	}{
		{"punchWait", t.PunchWait},
		{"punch", t.Punch},
		{"seed", t.Seed},
		{"backoff", t.Backoff},
		{"derpKeepAlive", t.DerpKeepAlive},
	} {
		if v.val < 0 {
			return fmt.Errorf("timeouts.%s must be positive", v.name)
		}
	}

	// Resolve and validate both keepalive pairs before applying anything, so a
	// rejected value never leaves half-applied state behind.
	relayInterval, relayTimeout, err := resolveSmuxTimeouts(t.Smux, "smux", time.Duration(smuxKeepAliveInterval.Load()), time.Duration(smuxKeepAliveTimeout.Load()))
	if err != nil {
		return err
	}
	directInterval, directTimeout, err := resolveSmuxTimeouts(t.DirectSmux, "directSmux", directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout)
	if err != nil {
		return err
	}

	// Validation passed: apply.
	if t.PunchWait != 0 {
		punchWaitTimeout = t.PunchWait
	}
	if t.Punch != 0 {
		punchTimeout = t.Punch
	}
	if t.Seed != 0 {
		seedTimeout = t.Seed
	}
	if t.Backoff != 0 {
		backoffPeriod.Store(int64(t.Backoff))
	}
	if t.DerpKeepAlive != 0 {
		keepAlivePeriod = t.DerpKeepAlive
	}
	smuxKeepAliveInterval.Store(int64(relayInterval))
	smuxKeepAliveTimeout.Store(int64(relayTimeout))
	directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout = directInterval, directTimeout
	return nil
}

// resolveSmuxTimeouts merges a smux timeouts block over the current values and
// checks the pair, naming the block in any error. A nil block or a zero field
// keeps what is already there.
func resolveSmuxTimeouts(s *p2p.SmuxTimeouts, name string, interval, timeout time.Duration) (time.Duration, time.Duration, error) {
	if s == nil {
		return interval, timeout, nil
	}
	if s.Interval < 0 || s.Timeout < 0 {
		return 0, 0, fmt.Errorf("timeouts.%s values must be positive", name)
	}
	if s.Interval != 0 {
		interval = s.Interval
	}
	if s.Timeout != 0 {
		timeout = s.Timeout
	}
	if timeout < 2*interval {
		return 0, 0, fmt.Errorf("timeouts.%s.timeout (%s) must be >= 2x interval (%s)", name, timeout, interval)
	}
	return interval, timeout, nil
}
