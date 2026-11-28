package host

import (
	"testing"
	"time"

	"github.com/go-gost/p2p"
)

func TestResolvePunchDefaults(t *testing.T) {
	got, err := resolvePunch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.mode != "" || got.afterRounds != 1 || got.sprayPorts != 1000 ||
		got.sprayEvery != 2*time.Second || got.sockets != 150 ||
		got.socketWindow != 20*time.Second || got.seedGrace != 500*time.Millisecond {
		t.Fatalf("defaults = %+v", got)
	}
}

func TestResolvePunchRejectsUnknownMode(t *testing.T) {
	if _, err := resolvePunch(&p2p.PunchConfig{Mode: "sprayx"}); err == nil {
		t.Fatal("want error for unknown mode")
	}
}

func TestResolvePunchClampsAndValidates(t *testing.T) {
	got, err := resolvePunch(&p2p.PunchConfig{Mode: "spray", SprayPorts: 99999, Sockets: 99999})
	if err != nil {
		t.Fatal(err)
	}
	if got.sprayPorts != 2048 || got.sockets != 512 {
		t.Fatalf("clamp = %+v", got)
	}
	for _, bad := range []*p2p.PunchConfig{
		{Mode: "spray", SprayEvery: 100 * time.Millisecond},
		{Mode: "sockets", SocketWindow: 61 * time.Second},
	} {
		if _, err := resolvePunch(bad); err == nil {
			t.Fatalf("want error for %+v", bad)
		}
	}
}
