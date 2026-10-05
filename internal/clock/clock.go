// Package clock provides a coarse wall clock for the packet path.
//
// Stamping liveness or arming a deadline once per packet is a real cost on the
// relay data path, and time.Now() is not free: where the clocksource is not
// the TSC, a read is an actual clock access that costs microseconds instead of
// nanoseconds, and a handful of per-frame stamps then account for a fifth of
// everything the relay burns. This clock keeps a wall time refreshed by a
// background tick and hands that value out, at the cost of up to one tick of
// lag.
//
// It is for stamping and for amortizing a deadline across frames, not for
// measuring elapsed time: a caller that needs the true elapsed time, or a
// timeout that must fire to the microsecond, must use the time package.
package clock

import (
	"sync"
	"sync/atomic"
	"time"
)

// Resolution is the staleness bound of Now: a value it returns is never more
// than one tick old. A deadline armed from it therefore expires no earlier
// than Resolution after the call, which is what lets a caller reuse one armed
// deadline across frames.
const Resolution = time.Millisecond

var (
	now  atomic.Int64 // UnixNano of the last tick, 0 before the clock starts
	once sync.Once
)

// Now returns the wall time of the most recent tick.
func Now() time.Time {
	once.Do(run)
	t := now.Load()
	if t == 0 {
		// The clock has not started yet (nothing has called it, or the first
		// call is racing the first tick): read the system clock once.
		return time.Now()
	}
	return time.Unix(0, t)
}

// UnixNano returns Now as Unix nanoseconds. Prefer it over Now where only the
// number is needed: it skips building a time.Time.
func UnixNano() int64 {
	once.Do(run)
	if t := now.Load(); t != 0 {
		return t
	}
	return time.Now().UnixNano()
}

// Since returns the time elapsed since t, measured against this clock. The
// result carries up to Resolution of error, so it is for coarse ages (idle
// peers, stale stamps), not for timing a race.
func Since(t time.Time) time.Duration { return Now().Sub(t) }

func run() {
	now.Store(time.Now().UnixNano())
	t := time.NewTicker(Resolution)
	go func() {
		defer t.Stop()
		// The ticker sends the time the tick fired, so the value comes from the
		// runtime timer instead of costing another clock read.
		for tick := range t.C {
			now.Store(tick.UnixNano())
		}
	}()
}
