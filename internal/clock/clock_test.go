package clock

import (
	"testing"
	"time"
)

func TestUnixNanoTracksTheSystemClock(t *testing.T) {
	got := UnixNano()
	if got == 0 {
		t.Fatal("UnixNano() = 0")
	}
	// A coarse clock is allowed to lag; it is not allowed to be from another
	// decade. Resolution plus slack covers a tick that has not landed yet.
	if drift := time.Now().UnixNano() - got; drift < 0 || drift > int64(50*time.Millisecond) {
		t.Errorf("UnixNano() is %v away from the system clock", time.Duration(drift))
	}
}

// TestClockAdvances is the property the liveness stamps depend on: a clock that
// stopped would report every peer as age zero forever, so nothing would ever be
// judged idle.
func TestClockAdvances(t *testing.T) {
	before := UnixNano()
	time.Sleep(10 * Resolution)
	after := UnixNano()
	if after <= before {
		t.Errorf("clock did not advance over 10 ticks: %d -> %d", before, after)
	}
}

// TestNowNeverGoesBackwards covers the direction the idle comparisons assume: a
// stamp taken later must never read as older than one taken before it.
func TestNowNeverGoesBackwards(t *testing.T) {
	prev := Now()
	for i := 0; i < 200; i++ {
		now := Now()
		if now.Before(prev) {
			t.Fatalf("Now() went backwards at iteration %d: %v after %v", i, now, prev)
		}
		prev = now
		time.Sleep(time.Millisecond)
	}
}

// TestSinceUsesThisClock pins the documented relationship instead of the system
// clock, which is the point of the package.
func TestSinceUsesThisClock(t *testing.T) {
	start := Now()
	time.Sleep(5 * Resolution)
	d := Since(start)
	if d < 4*Resolution || d > time.Second {
		t.Errorf("Since() = %v over a %v sleep", d, 5*Resolution)
	}
}
