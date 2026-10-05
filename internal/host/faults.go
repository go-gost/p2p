package host

import (
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-gost/p2p"
)

// faults is the process-wide injection state, built once from the config and
// read by every injection point on its hot path. The knobs are atomics and the
// readers take no lock: a disabled injection must cost a load, not a mutex. The
// whole state is held behind an atomic pointer (engine.faults) for the same
// reason the inbound queue is — a reader runs on the pump, the punch and every
// smux write, so the state can be handed in from outside those goroutines
// (tests do, to open a silence window on demand) without a race.
//
// None of this is reachable from a network API: it is built from the config file
// at startup and never changed again. See p2p.FaultsConfig.
type faults struct {
	dropCtrl, dropData, dropPong atomic.Bool

	// dropDataRate is the configured ratio, logged at startup. dropDataPeriod
	// is the precomputed drop interval (0 when disabled); dropDataSeq counts
	// calls on the hot path. The whole state is immutable after construction,
	// except for the counter which is bumped by dropDataPacket without a lock.
	dropDataRate   float64
	dropDataPeriod uint64
	dropDataSeq    atomic.Uint64

	// The timed mute's shape and its origin. The origin is the instant the fault
	// was built, so a host configured with silence starts muted and then sends
	// for SilenceEvery-SilenceFor before muting again. silenceEvery>0 is
	// required: a for-without-every would be a permanent mute, which is not a
	// reproducible failure but a broken host.
	silenceFor   time.Duration
	silenceEvery time.Duration
	since        time.Time

	// knobs names the enabled faults, computed once from the config. It feeds
	// only the startup announcement (warn) and the stub-mode "ignored" warning,
	// never the hot path.
	knobs []string
}

// newFaults builds the state and stamps the silence window's origin. cfg may be
// nil — the common case, everything off — and still yields a usable, inert
// state, so the readers never have to nil-check the config they came from.
func newFaults(cfg *p2p.FaultsConfig) *faults {
	if cfg == nil {
		return &faults{since: time.Now()}
	}
	f := &faults{
		silenceFor:   cfg.SilenceFor,
		silenceEvery: cfg.SilenceEvery,
		since:        time.Now(),
		dropDataRate: cfg.DropDataRate,
		knobs:        faultKnobs(cfg),
	}
	f.dropCtrl.Store(cfg.DropCtrl)
	f.dropData.Store(cfg.DropData)
	f.dropPong.Store(cfg.DropPong)
	if cfg.DropDataRate > 0 {
		period := uint64(math.Round(1 / cfg.DropDataRate))
		if period < 1 {
			period = 1
		}
		f.dropDataPeriod = period
	}
	return f
}

// warn logs the enabled knobs once, at startup. An injected drop is
// indistinguishable from a real one at every layer above, which is the point of
// the feature and the reason this line exists: a fault-injected host must never
// be read as a broken one.
func (f *faults) warn(log *slog.Logger) {
	if f == nil || log == nil || len(f.knobs) == 0 {
		return
	}
	log.Warn("p2p: fault injection is on — this host is deliberately dropping traffic",
		"faults", strings.Join(f.knobs, ","))
}

// faultKnobs names the enabled faults of a config, in the order warn reports
// them. It reads the config directly (not the built state) so the stub-mode
// path — which builds no state — can list what it is ignoring.
func faultKnobs(cfg *p2p.FaultsConfig) []string {
	if cfg == nil {
		return nil
	}
	var on []string
	if cfg.DropCtrl {
		on = append(on, "dropCtrl")
	}
	if cfg.DropData {
		on = append(on, "dropData")
	}
	if cfg.DropDataRate > 0 {
		on = append(on, fmt.Sprintf("dropDataRate(%g)", cfg.DropDataRate))
	}
	if cfg.DropPong {
		on = append(on, "dropPong")
	}
	if cfg.SilenceFor > 0 && cfg.SilenceEvery > 0 {
		on = append(on, "silence("+cfg.SilenceFor.String()+" every "+cfg.SilenceEvery.String()+")")
	}
	return on
}

// warnIgnoredFaults logs, once at startup, that a faults config cannot take
// effect because the host is in stub mode (no relay configured, so no engine to
// hold the state). A silent no-op here would read as "injection is on" and cost
// the same debugging the silent acceptance already did.
func warnIgnoredFaults(cfg *p2p.FaultsConfig, log *slog.Logger) {
	on := faultKnobs(cfg)
	if len(on) == 0 || log == nil {
		return
	}
	log.Warn("p2p: fault injection configured but ignored: no relay (derp) configured, so there is no plane to break",
		"faults", strings.Join(on, ","))
}

// pong reports whether pong handling is swallowed.
func (f *faults) pong() bool { return f != nil && f.dropPong.Load() }

// silenced reports whether the process is inside a silence window now. A
// silence covers both planes — control and data — because that is what the field
// failure looked like: a one-way silence from the peer, path intact.
func (f *faults) silenced(now time.Time) bool {
	if f == nil || f.silenceFor <= 0 || f.silenceEvery <= 0 {
		return false
	}
	off := now.Sub(f.since)
	if off < 0 {
		return false // the first window has not opened yet
	}
	return off%f.silenceEvery < f.silenceFor
}

// muteCtrl reports whether a control frame must be dropped now: the permanent
// fault, or a silence window (which covers control too).
func (f *faults) muteCtrl(now time.Time) bool {
	return f != nil && (f.dropCtrl.Load() || f.silenced(now))
}

// muteData reports whether a data frame must be dropped now, on either plane's
// send path or on delivery. The silence window is folded in here as well: a
// silence is a mute on the whole peer link, not a data-only one.
func (f *faults) muteData(now time.Time) bool {
	return f != nil && (f.dropData.Load() || f.silenced(now))
}

// muteDataArmed reports whether muteData can drop anything at all. Every packet
// path asks before building the timestamp muteData needs: with no fault
// configured — the shipping case — muteData is false whatever the time is, so
// the stamp would be pure per-packet overhead, and a clock read is expensive
// enough on a host without a TSC to show up in a profile of the relay.
func (f *faults) muteDataArmed() bool {
	return f != nil && (f.dropData.Load() || f.silencedArmed())
}

// silencedArmed reports whether any silence window is configured. It is the
// cheap half of silenced: the window arithmetic needs a timestamp, the
// configuration alone does not.
func (f *faults) silencedArmed() bool {
	return f != nil && f.silenceFor > 0 && f.silenceEvery > 0
}

// dropDataPacket reports whether this relay data frame must be dropped now.
// It is deterministic: a configured rate of r drops every round(1/r)th frame.
// The counter is per-faults state, so a rebuilt faults resets the sequence.
func (f *faults) dropDataPacket() bool {
	if f == nil || f.dropDataPeriod == 0 {
		return false
	}
	return f.dropDataSeq.Add(1)%f.dropDataPeriod == 0
}
