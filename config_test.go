package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// TestLoadConfig covers parsing the full YAML schema, including the *bool
// "secure" (which must distinguish an explicit false from an omitted value).
func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p2p.yaml")

	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write(`addr: 0.0.0.0:8003
token: gost
derp: wss://derp.example.com/derp
key: peer.key
target: 127.0.0.1:18080
stun: stun.example.com:3478
tls:
  secure: false
  caFile: /etc/p2p/ca.pem
log:
  level: debug
  format: text
  output: stdout
  rotation:
    maxSize: 50
    maxAge: 7
    maxBackups: 3
    localTime: true
    compress: true
forwards:
  - listen: 127.0.0.1:18080
    peer: abc
  - listen: 127.0.0.1:18081
    peer: def
timeouts:
  punchWait: 7s
  backoff: 45s
  smux:
    interval: 5s
    timeout: 10s
`)
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "0.0.0.0:8003" || c.Token != "gost" ||
		c.Derp != "wss://derp.example.com/derp" || c.Key != "peer.key" ||
		c.Target != "127.0.0.1:18080" || c.Stun != "stun.example.com:3478" {
		t.Fatalf("flat fields = %+v", c)
	}
	if c.TLS == nil || c.TLS.Secure == nil || *c.TLS.Secure != false || c.TLS.CAFile != "/etc/p2p/ca.pem" {
		t.Fatalf("tls = %+v", c.TLS)
	}
	if c.Log == nil || c.Log.Level != "debug" || c.Log.Format != "text" || c.Log.Output != "stdout" {
		t.Fatalf("log = %+v", c.Log)
	}
	if c.Log.Rotation == nil || c.Log.Rotation.MaxSize != 50 || c.Log.Rotation.MaxAge != 7 ||
		c.Log.Rotation.MaxBackups != 3 || !c.Log.Rotation.LocalTime || !c.Log.Rotation.Compress {
		t.Fatalf("rotation = %+v", c.Log.Rotation)
	}
	if len(c.Forwards) != 2 || c.Forwards[0].Listen != "127.0.0.1:18080" || c.Forwards[0].Peer != "abc" ||
		c.Forwards[1].Listen != "127.0.0.1:18081" || c.Forwards[1].Peer != "def" {
		t.Fatalf("forwards = %+v", c.Forwards)
	}
	if c.Timeouts == nil || c.Timeouts.PunchWait != 7*time.Second || c.Timeouts.Backoff != 45*time.Second {
		t.Fatalf("timeouts = %+v", c.Timeouts)
	}
	if c.Timeouts.Smux == nil || c.Timeouts.Smux.Interval != 5*time.Second || c.Timeouts.Smux.Timeout != 10*time.Second {
		t.Fatalf("timeouts.smux = %+v", c.Timeouts.Smux)
	}

	// omitted secure -> nil pointer (so the merge keeps the default true)
	write("tls:\n  caFile: /ca.pem\n")
	c, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.TLS == nil || c.TLS.Secure != nil {
		t.Fatalf("omitted secure = %+v, want nil pointer", c.TLS)
	}

	// malformed YAML -> error
	write("addr: [unclosed\n")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("malformed yaml = nil error")
	}

	// missing file -> error
	if _, err := loadConfig(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing file = nil error")
	}

	// empty file -> zero-value config
	write("")
	c, err = loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Forwards) != 0 || c.TLS != nil || c.Log != nil || c.Addr != "" {
		t.Fatalf("empty config = %+v, want zero value", c)
	}
}

// TestLogOutputRotation verifies the log.rotation config reaches lumberjack's
// fields, and that a nil rotation falls back to lumberjack defaults.
func TestLogOutputRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "app.log")

	w, err := logOutput(path, &LogRotationConfig{
		MaxSize: 25, MaxAge: 3, MaxBackups: 2, LocalTime: true, Compress: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	lj, ok := w.(*lumberjack.Logger)
	if !ok {
		t.Fatalf("logOutput = %T, want *lumberjack.Logger", w)
	}
	if lj.Filename != path || lj.MaxSize != 25 || lj.MaxAge != 3 ||
		lj.MaxBackups != 2 || !lj.LocalTime || !lj.Compress {
		t.Fatalf("lumberjack = %+v", lj)
	}

	// nil rotation -> lumberjack defaults (zero MaxSize = default 100 MB)
	w2, err := logOutput(filepath.Join(dir, "def.log"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if lj2 := w2.(*lumberjack.Logger); lj2.MaxSize != 0 || lj2.MaxBackups != 0 || lj2.Compress {
		t.Fatalf("nil rotation lumberjack = %+v", lj2)
	}

	// non-file output is not a lumberjack logger
	if _, err := logOutput("stderr", &LogRotationConfig{MaxSize: 1}); err != nil {
		t.Fatal(err)
	}
}

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
	if err := applyTimeouts(&TimeoutsConfig{}); err != nil {
		t.Fatalf("zero: %v", err)
	}
	if punchWaitTimeout != oldPunchWait || smuxKeepAliveInterval != oldI {
		t.Fatal("zero config changed defaults")
	}

	// negative rejected
	if err := applyTimeouts(&TimeoutsConfig{PunchWait: -time.Second}); err == nil {
		t.Fatal("negative punchWait accepted")
	}

	// smux timeout < 2x interval rejected (equality is the historical footgun)
	if err := applyTimeouts(&TimeoutsConfig{Smux: &SmuxTimeouts{
		Interval: 10 * time.Second, Timeout: 19 * time.Second,
	}}); err == nil {
		t.Fatal("smux timeout < 2x interval accepted")
	}

	// valid: applied
	if err := applyTimeouts(&TimeoutsConfig{
		PunchWait: 7 * time.Second,
		Backoff:   45 * time.Second,
		Smux:      &SmuxTimeouts{Interval: 5 * time.Second, Timeout: 10 * time.Second},
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
