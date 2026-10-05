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
//
// Only the lower bound is a property of this package: both ends of the
// subtraction are this clock, so each can lag the system clock by up to
// Resolution, and Since can under-report a real sleep by up to two ticks. The
// upper bound is deliberately loose because it measures the *scheduler*, not
// the clock — time.Sleep overshoots by an unbounded amount under load, so
// asserting a tight ceiling here would only measure how busy the machine was.
func TestSinceUsesThisClock(t *testing.T) {
	const sleep = 5 * Resolution
	start := Now()
	time.Sleep(sleep)
	d := Since(start)
	if min := sleep - 2*Resolution; d < min {
		t.Errorf("Since() = %v over a %v sleep, want at least %v: staleness must cost at most two ticks",
			d, sleep, min)
	}
	if d > time.Second {
		t.Errorf("Since() = %v over a %v sleep, want at most a second", d, sleep)
	}
}
