package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadConfig covers parsing the full YAML schema — the endpoint keys stay
// top-level through the inlined p2p.Config, and the CLI's own keys (addr,
// token, log) parse alongside them. The *bool "secure" must distinguish an
// explicit false from an omitted value.
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

	// omitted secure -> nil pointer (so the endpoint keeps the default true)
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

// TestConfigTargetsMerge: the legacy scalar `target` and the `targets` list
// merge into one list (scalar first), and either alone works.
func TestConfigTargetsMerge(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p2p.yaml")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	write("target: 127.0.0.1:18080\ntargets:\n  - udp://127.0.0.1:8421\n  - 127.0.0.1:18081\n")
	c, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"127.0.0.1:18080", "udp://127.0.0.1:8421", "127.0.0.1:18081"}
	if got := c.TargetList(); !equalStrings(got, want) {
		t.Fatalf("merged targets = %q, want %q", got, want)
	}

	write("targets:\n  - udp://127.0.0.1:8421\n")
	if c, _ = loadConfig(path); !equalStrings(c.TargetList(), []string{"udp://127.0.0.1:8421"}) {
		t.Fatalf("list only = %q", c.TargetList())
	}

	write("target: 127.0.0.1:18080\n")
	if c, _ = loadConfig(path); !equalStrings(c.TargetList(), []string{"127.0.0.1:18080"}) {
		t.Fatalf("scalar only = %q", c.TargetList())
	}

	write("")
	if c, _ = loadConfig(path); len(c.TargetList()) != 0 {
		t.Fatalf("empty = %q, want none", c.TargetList())
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
