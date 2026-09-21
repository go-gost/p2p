package p2p

import "testing"

// TestParseTarget: a bare host:port is tcp; an explicit scheme selects the
// network; anything malformed or unsupported is rejected.
func TestParseTarget(t *testing.T) {
	ok := []struct {
		in      string
		network string
		addr    string
	}{
		{"127.0.0.1:18080", "tcp", "127.0.0.1:18080"},
		{"udp://127.0.0.1:8421", "udp", "127.0.0.1:8421"},
		{"tcp://[::1]:9000", "tcp", "[::1]:9000"},
		{"example.com:443", "tcp", "example.com:443"},
	}
	for _, c := range ok {
		got, err := parseTarget(c.in)
		if err != nil {
			t.Fatalf("parseTarget(%q): %v", c.in, err)
		}
		if got.network != c.network || got.addr != c.addr {
			t.Fatalf("parseTarget(%q) = {%q, %q}, want {%q, %q}", c.in, got.network, got.addr, c.network, c.addr)
		}
	}

	for _, in := range []string{"", "  ", "127.0.0.1", "udp://", "quic://1.2.3.4:5", "udp://127.0.0.1"} {
		if _, err := parseTarget(in); err == nil {
			t.Fatalf("parseTarget(%q) accepted, want error", in)
		}
	}
}

// TestTargetPoolPick: round-robin within a network, and networks are
// independent — a tcp pick does not advance the udp cursor.
func TestTargetPoolPick(t *testing.T) {
	p := newTargetPool()
	mustAdd(t, p, "127.0.0.1:10001", "127.0.0.1:10002", "udp://127.0.0.1:20001", "udp://127.0.0.1:20002")

	var tcp []string
	for i := 0; i < 4; i++ {
		a, ok := p.pick("tcp")
		if !ok {
			t.Fatal("pick(tcp) found no target")
		}
		tcp = append(tcp, a)
	}
	if want := []string{"127.0.0.1:10001", "127.0.0.1:10002", "127.0.0.1:10001", "127.0.0.1:10002"}; !equalStrings(tcp, want) {
		t.Fatalf("tcp round-robin = %q, want %q", tcp, want)
	}

	// udp's cursor is its own: the first udp pick is the first udp target.
	if a, _ := p.pick("udp"); a != "127.0.0.1:20001" {
		t.Fatalf("first udp pick = %q, want 127.0.0.1:20001", a)
	}
	if a, _ := p.pick("udp"); a != "127.0.0.1:20002" {
		t.Fatalf("second udp pick = %q, want 127.0.0.1:20002", a)
	}
}

// TestTargetPoolEmpty: an absent network yields no target rather than a panic.
func TestTargetPoolEmpty(t *testing.T) {
	p := newTargetPool()
	if _, ok := p.pick("tcp"); ok {
		t.Fatal("empty pool returned a tcp target")
	}
	if _, ok := p.pick("udp"); ok {
		t.Fatal("empty pool returned a udp target")
	}
	if p.has("tcp") || p.has("udp") {
		t.Fatal("empty pool reports a network it does not have")
	}
	mustAdd(t, p, "udp://127.0.0.1:8421")
	if p.has("tcp") {
		t.Fatal("tcp reported present while only a udp target was added")
	}
	if !p.has("udp") {
		t.Fatal("udp reported absent after being added")
	}
}

func mustAdd(t *testing.T, p *targetPool, specs ...string) {
	t.Helper()
	for _, s := range specs {
		sp, err := parseTarget(s)
		if err != nil {
			t.Fatalf("parseTarget(%q): %v", s, err)
		}
		p.add(sp)
	}
}
