package host

import (
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

// TestApplyTimeouts covers validation and application of the timeouts section:
// zero values keep defaults, invalid values are rejected, and a valid set is
// applied to the package-level timing vars.
func TestApplyTimeouts(t *testing.T) {
	oldPunchWait, oldBackoff := punchWaitTimeout, backoffPeriod
	oldI, oldT := smuxKeepAliveInterval, smuxKeepAliveTimeout
	t.Cleanup(func() {
		punchWaitTimeout, backoffPeriod = oldPunchWait, oldBackoff
		smuxKeepAliveInterval, smuxKeepAliveTimeout = oldI, oldT
	})

	// nil and zero values: no-op
	if err := applyTimeouts(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := applyTimeouts(&p2p.TimeoutsConfig{}); err != nil {
		t.Fatalf("zero: %v", err)
	}
	if punchWaitTimeout != oldPunchWait || smuxKeepAliveInterval != oldI {
		t.Fatal("zero config changed defaults")
	}

	// negative rejected
	if err := applyTimeouts(&p2p.TimeoutsConfig{PunchWait: -time.Second}); err == nil {
		t.Fatal("negative punchWait accepted")
	}

	// smux timeout < 2x interval rejected (equality is the historical footgun)
	if err := applyTimeouts(&p2p.TimeoutsConfig{Smux: &p2p.SmuxTimeouts{
		Interval: 10 * time.Second, Timeout: 19 * time.Second,
	}}); err == nil {
		t.Fatal("smux timeout < 2x interval accepted")
	}

	// valid: applied
	if err := applyTimeouts(&p2p.TimeoutsConfig{
		PunchWait: 7 * time.Second,
		Backoff:   45 * time.Second,
		Smux:      &p2p.SmuxTimeouts{Interval: 5 * time.Second, Timeout: 10 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	if punchWaitTimeout != 7*time.Second || backoffPeriod != 45*time.Second {
		t.Fatalf("punchWait=%v backoff=%v", punchWaitTimeout, backoffPeriod)
	}
	if smuxKeepAliveInterval != 5*time.Second || smuxKeepAliveTimeout != 10*time.Second {
		t.Fatalf("smux=%v/%v", smuxKeepAliveInterval, smuxKeepAliveTimeout)
	}
}

// TestApplyDefaults pins the library-side defaults: an omitted tls/direct block
// means secure and direct-on, and an explicit false survives.
func TestApplyDefaults(t *testing.T) {
	cfg := &p2p.Config{}
	applyDefaults(cfg)
	if cfg.TLS == nil || cfg.TLS.Secure == nil || !*cfg.TLS.Secure {
		t.Fatalf("default TLS = %+v, want secure=true", cfg.TLS)
	}
	if cfg.Direct == nil || !*cfg.Direct {
		t.Fatalf("default Direct = %v, want true", cfg.Direct)
	}

	off := false
	cfg = &p2p.Config{TLS: &p2p.TLSConfig{Secure: &off}, Direct: &off}
	applyDefaults(cfg)
	if *cfg.TLS.Secure || *cfg.Direct {
		t.Fatal("explicit false was overwritten by the defaults")
	}
}
