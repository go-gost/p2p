package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/goccy/go-yaml"
)

// Config is the optional YAML configuration file. Every field mirrors a
// command-line flag (the flag name without the leading "--"); a config value
// supplies the default and an explicitly-set flag overrides it.
type Config struct {
	Addr     string          `yaml:"addr,omitempty"`
	Bind     string          `yaml:"bind,omitempty"`
	Token    string          `yaml:"token,omitempty"`
	Derp     string          `yaml:"derp,omitempty"`
	Key      string          `yaml:"key,omitempty"`
	Target   string          `yaml:"target,omitempty"`
	Stun     string          `yaml:"stun,omitempty"`
	TLS      *TLSConfig      `yaml:"tls,omitempty"`
	Log      *LogConfig      `yaml:"log,omitempty"`
	Timeouts *TimeoutsConfig `yaml:"timeouts,omitempty"`
	Forwards []ForwardConfig `yaml:"forwards,omitempty"`
}

// TimeoutsConfig tunes deployment-dependent timings. Zero values keep the
// built-in defaults; internal mechanism timeouts stay hardcoded.
type TimeoutsConfig struct {
	PunchWait     time.Duration `yaml:"punchWait,omitempty"`
	Punch         time.Duration `yaml:"punch,omitempty"`
	Seed          time.Duration `yaml:"seed,omitempty"`
	Backoff       time.Duration `yaml:"backoff,omitempty"`
	DerpKeepAlive time.Duration `yaml:"derpKeepAlive,omitempty"`
	Smux          *SmuxTimeouts `yaml:"smux,omitempty"`
}

// SmuxTimeouts tunes the smux keepalive shared by the relay and direct
// sessions. Timeout must be >= 2x Interval (validated in applyTimeouts).
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

// LogConfig mirrors the --log.* flags plus file rotation.
type LogConfig struct {
	Level    string             `yaml:"level,omitempty"`
	Format   string             `yaml:"format,omitempty"`
	Output   string             `yaml:"output,omitempty"`
	Rotation *LogRotationConfig `yaml:"rotation,omitempty"`
}

// LogRotationConfig configures lumberjack file rotation for a file output.
// Zero values fall back to lumberjack's defaults (100 MB, keep all, UTC, no
// compression).
type LogRotationConfig struct {
	MaxSize    int  `yaml:"maxSize,omitempty"`
	MaxAge     int  `yaml:"maxAge,omitempty"`
	MaxBackups int  `yaml:"maxBackups,omitempty"`
	LocalTime  bool `yaml:"localTime,omitempty"`
	Compress   bool `yaml:"compress,omitempty"`
}

// ForwardConfig is a pre-configured static port forward: bind Listen and bridge
// accepted connections to the peer's public key.
type ForwardConfig struct {
	Listen string `yaml:"listen,omitempty"`
	Peer   string `yaml:"peer,omitempty"`
}

// loadConfig reads and parses a YAML config file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &c, nil
}

// applyTimeouts validates and applies the timeouts config to the package-level
// timing vars. Zero values keep defaults; invalid values are rejected at
// startup so a misconfiguration fails loudly instead of producing a silently
// broken punch. smux timeout must be >= 2x the interval: smux's own
// VerifyConfig only requires >=, and the failing case hit twice was equality
// (an idle session kills itself after ~interval).
func applyTimeouts(t *TimeoutsConfig) error {
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
	if t.Smux != nil && (t.Smux.Interval < 0 || t.Smux.Timeout < 0) {
		return errors.New("timeouts.smux values must be positive")
	}

	// Validate the smux pair before applying anything, so a rejected value
	// never leaves half-applied state behind.
	if t.Smux != nil {
		interval, timeout := smuxKeepAliveInterval, smuxKeepAliveTimeout
		if t.Smux.Interval != 0 {
			interval = t.Smux.Interval
		}
		if t.Smux.Timeout != 0 {
			timeout = t.Smux.Timeout
		}
		if timeout < 2*interval {
			return fmt.Errorf("timeouts.smux.timeout (%s) must be >= 2x interval (%s)", timeout, interval)
		}
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
	if t.Smux != nil {
		if t.Smux.Interval != 0 {
			smuxKeepAliveInterval = t.Smux.Interval
		}
		if t.Smux.Timeout != 0 {
			smuxKeepAliveTimeout = t.Smux.Timeout
		}
	}
	return nil
}
