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

// applyTimeouts validates and applies the timeouts config to the package-level
// timing vars. Zero values keep defaults; invalid values are rejected at
// startup so a misconfiguration fails loudly instead of producing a silently
// broken punch. smux timeout must be >= 2x the interval: smux's own
// VerifyConfig only requires >=, and the failing case hit twice was equality
// (an idle session kills itself after ~interval).
//
// The timings are process-wide, not per-Host: a second New merges its non-zero
// values into those already applied, so a Host with zero timeouts inherits the
// first Host's. One endpoint per process is the model (see p2p.TimeoutsConfig).
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
	relayInterval, relayTimeout, err := resolveSmuxTimeouts(t.Smux, "smux", smuxKeepAliveInterval, smuxKeepAliveTimeout)
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
		backoffPeriod = t.Backoff
	}
	if t.DerpKeepAlive != 0 {
		keepAlivePeriod = t.DerpKeepAlive
	}
	smuxKeepAliveInterval, smuxKeepAliveTimeout = relayInterval, relayTimeout
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
