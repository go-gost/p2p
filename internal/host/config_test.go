package host

import (
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

// shippedDirectSmuxTimeout is read before TestMain shortens the timing globals
// (package-level initialisers run first), so the floor below is checked against
// what production ships rather than against test speed.
var shippedDirectSmuxTimeout = directSmuxKeepAliveTimeout

// TestDirectKeepAliveCoversTheMeasuredSilence pins the direct session's timeout
// as a silence budget. A phone on Wi-Fi lost its direct session at exactly
// 18.000s (~3 ticks of the 6s timeout it then was), and the cause was ~12s of
// one-way silence from RF batching — so a timeout at or below that window
// re-introduces the churn. The mechanism itself is what
// TestDirectSilentPeerIsNoticed measures; this is the value it is given.
func TestDirectKeepAliveCoversTheMeasuredSilence(t *testing.T) {
	const measuredSilence = 12 * time.Second
	if shippedDirectSmuxTimeout <= measuredSilence {
		t.Fatalf("direct keepalive timeout %s must exceed the measured %s of one-way silence (see engine.go)",
			shippedDirectSmuxTimeout, measuredSilence)
	}
}

// TestApplyTimeouts covers validation and application of the timeouts section:
// zero values keep defaults, invalid values are rejected, and a valid set is
// applied to the package-level timing vars.
func TestApplyTimeouts(t *testing.T) {
	oldPunchWait := punchWaitTimeout
	oldBackoff := backoffPeriod.Load()
	oldI, oldT := smuxKeepAliveInterval.Load(), smuxKeepAliveTimeout.Load()
	oldDI, oldDT := directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout
	t.Cleanup(func() {
		punchWaitTimeout = oldPunchWait
		backoffPeriod.Store(oldBackoff)
		smuxKeepAliveInterval.Store(oldI)
		smuxKeepAliveTimeout.Store(oldT)
		directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout = oldDI, oldDT
	})

	// nil and zero values: no-op
	if err := applyTimeouts(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := applyTimeouts(&p2p.TimeoutsConfig{}); err != nil {
		t.Fatalf("zero: %v", err)
	}
	if punchWaitTimeout != oldPunchWait || smuxKeepAliveInterval.Load() != oldI || directSmuxKeepAliveInterval != oldDI {
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
	if err := applyTimeouts(&p2p.TimeoutsConfig{DirectSmux: &p2p.SmuxTimeouts{
		Interval: 5 * time.Second, Timeout: 9 * time.Second,
	}}); err == nil {
		t.Fatal("directSmux timeout < 2x interval accepted")
	}
	// A rejected direct block leaves the relay pair alone too: both are
	// validated before either is applied.
	if smuxKeepAliveInterval.Load() != oldI || smuxKeepAliveTimeout.Load() != oldT {
		t.Fatal("a rejected directSmux block changed the relay keepalive")
	}

	// valid: applied, and the two pairs are independent
	if err := applyTimeouts(&p2p.TimeoutsConfig{
		PunchWait:  7 * time.Second,
		Backoff:    45 * time.Second,
		Smux:       &p2p.SmuxTimeouts{Interval: 5 * time.Second, Timeout: 10 * time.Second},
		DirectSmux: &p2p.SmuxTimeouts{Interval: time.Second, Timeout: 3 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	if punchWaitTimeout != 7*time.Second || time.Duration(backoffPeriod.Load()) != 45*time.Second {
		t.Fatalf("punchWait=%v backoff=%v", punchWaitTimeout, time.Duration(backoffPeriod.Load()))
	}
	if smuxKeepAliveInterval.Load() != int64(5*time.Second) || smuxKeepAliveTimeout.Load() != int64(10*time.Second) {
		t.Fatalf("smux=%v/%v", time.Duration(smuxKeepAliveInterval.Load()), time.Duration(smuxKeepAliveTimeout.Load()))
	}
	if directSmuxKeepAliveInterval != time.Second || directSmuxKeepAliveTimeout != 3*time.Second {
		t.Fatalf("directSmux=%v/%v", directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout)
	}

	// A block that names only one field keeps the other's current value.
	if err := applyTimeouts(&p2p.TimeoutsConfig{DirectSmux: &p2p.SmuxTimeouts{Interval: time.Second}}); err != nil {
		t.Fatal(err)
	}
	if directSmuxKeepAliveInterval != time.Second || directSmuxKeepAliveTimeout != 3*time.Second {
		t.Fatalf("partial directSmux = %v/%v, want the timeout kept", directSmuxKeepAliveInterval, directSmuxKeepAliveTimeout)
	}
}

// TestTransportConfigDefaults pins the transport selector: an omitted value and
// "kcp" keep the existing data plane, "quic" opts in.
func TestTransportConfigDefaults(t *testing.T) {
	cases := []struct {
		in   string
		want transportMode
	}{
		{"", transportKCP}, {"kcp", transportKCP}, {"quic", transportQUIC},
	}
	for _, c := range cases {
		cfg := &p2p.Config{Transport: c.in, Derp: "ws://example"}
		got, err := resolveTransport(cfg)
		if err != nil || got != c.want {
			t.Fatalf("%q: got %v, %v", c.in, got, err)
		}
	}
}

// TestTransportConfigRejectsUnknown: a mode other than kcp/quic is a startup
// error rather than a silent fall back to KCP.
func TestTransportConfigRejectsUnknown(t *testing.T) {
	if _, err := resolveTransport(&p2p.Config{Transport: "sctp", Derp: "ws://example"}); err == nil {
		t.Fatal("want error")
	}
}

// TestKCPModeBuildsNoQUICState pins the default transport's promise: KCP mode
// creates no QUIC identity, no QUIC transport state, and advertises the legacy
// caps byte with no QUIC bit or TLV.
func TestKCPModeBuildsNoQUICState(t *testing.T) {
	h, err := New(&p2p.Config{Derp: "http://127.0.0.1:1", Key: strings.Repeat("cc", 32)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })

	e := h.engine
	if e == nil {
		t.Fatal("no engine in relay mode")
	}
	if e.transport != transportKCP {
		t.Fatalf("transport = %v, want kcp", e.transport)
	}
	if e.quicID != nil {
		t.Fatal("KCP mode created a QUIC identity")
	}
	if len(e.quics) != 0 {
		t.Fatalf("KCP mode holds %d QUIC peer states", len(e.quics))
	}
	info := e.caps()
	if info.Bits&capsQUIC != 0 || info.QUIC != nil {
		t.Fatalf("KCP caps = %+v, want no QUIC bit/TLV", info)
	}
	if got := encodeCaps(info); len(got) != 1 {
		t.Fatalf("KCP caps encoded %d bytes, want the legacy one-byte form", len(got))
	}
}

// TestQUICConfigValidation pins the QUIC defaults and rejects every value the
// spec limits: mtu >= 1200, batch <= 64 KiB, idle > keepalive, and a positive
// handshake timeout. QUIC mode also requires a relay (DERP) mode.
func TestQUICConfigValidation(t *testing.T) {
	got, err := resolveQUICSettings(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := quicSettings{
		MTU:              1200,
		RelayBatchBytes:  32768,
		RelayFlush:       200 * time.Microsecond,
		KeepAlive:        5 * time.Second,
		Idle:             15 * time.Second,
		HandshakeTimeout: 10 * time.Second,
	}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}

	for _, c := range []struct {
		name string
		cfg  *p2p.QUICConfig
	}{
		{"mtu below 1200", &p2p.QUICConfig{MTU: 1199}},
		{"batch above 64 KiB", &p2p.QUICConfig{RelayBatchBytes: 65537}},
		{"idle not above keepalive", &p2p.QUICConfig{KeepAlive: 5 * time.Second, Idle: 5 * time.Second}},
		{"negative handshake timeout", &p2p.QUICConfig{HandshakeTimeout: -time.Second}},
	} {
		if _, err := resolveQUICSettings(c.cfg); err == nil {
			t.Fatalf("%s: want error", c.name)
		}
	}

	// QUIC is strict: it needs the relay path, so stub mode cannot select it.
	if _, err := New(&p2p.Config{Transport: "quic"}); err == nil {
		t.Fatal("New accepted transport=quic without derp")
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
