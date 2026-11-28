package host

import (
	"fmt"
	"time"

	"github.com/go-gost/p2p"
)

const (
	defaultPunchAfterRounds  = 1
	defaultPunchSprayPorts   = 1000
	maxPunchSprayPorts       = 2048
	defaultPunchSprayEvery   = 2 * time.Second
	minPunchSprayEvery       = time.Second
	defaultPunchSockets      = 150
	maxPunchSockets          = 512
	defaultPunchSocketWindow = 20 * time.Second
	maxPunchSocketWindow     = 60 * time.Second
	defaultPunchSeedGrace    = 500 * time.Millisecond
)

// punchSettings is the resolved, validated fallback configuration. A zero mode
// means the fallback is off and the existing punch path is unchanged.
type punchSettings struct {
	mode         string
	afterRounds  int
	sprayPorts   int
	sockets      int
	sprayEvery   time.Duration
	socketWindow time.Duration
	seedGrace    time.Duration
}

// sprayEnabled reports whether this host opted into the spray/sockets punch
// fallback and therefore advertises capsSpray.
func (e *engine) sprayEnabled() bool {
	return e.punch.mode == "spray" || e.punch.mode == "sockets"
}

// resolvePunch merges the punch block over the built-in defaults and validates
// the result. Zero fields keep their defaults; "off" normalizes to "".
func resolvePunch(c *p2p.PunchConfig) (punchSettings, error) {
	s := punchSettings{
		afterRounds:  defaultPunchAfterRounds,
		sprayPorts:   defaultPunchSprayPorts,
		sprayEvery:   defaultPunchSprayEvery,
		sockets:      defaultPunchSockets,
		socketWindow: defaultPunchSocketWindow,
		seedGrace:    defaultPunchSeedGrace,
	}
	if c == nil {
		return s, nil
	}

	switch c.Mode {
	case "", "off":
	case "spray", "sockets":
		s.mode = c.Mode
	default:
		return punchSettings{}, fmt.Errorf("punch.mode: unknown mode %q (want spray or sockets)", c.Mode)
	}
	if s.mode == "" {
		return s, nil
	}

	if c.AfterRounds < 0 {
		return punchSettings{}, fmt.Errorf("punch.afterRounds must not be negative")
	}
	if c.AfterRounds > 0 {
		s.afterRounds = c.AfterRounds
	}

	if c.SprayPorts < 0 {
		return punchSettings{}, fmt.Errorf("punch.sprayPorts must not be negative")
	}
	if c.SprayPorts > 0 {
		s.sprayPorts = c.SprayPorts
		if s.sprayPorts > maxPunchSprayPorts {
			s.sprayPorts = maxPunchSprayPorts
		}
	}

	if c.SprayEvery < 0 {
		return punchSettings{}, fmt.Errorf("punch.sprayEvery must not be negative")
	}
	if c.SprayEvery > 0 {
		s.sprayEvery = c.SprayEvery
	}
	if s.sprayEvery < minPunchSprayEvery {
		return punchSettings{}, fmt.Errorf("punch.sprayEvery (%s) must be at least %s", s.sprayEvery, minPunchSprayEvery)
	}

	if c.Sockets < 0 {
		return punchSettings{}, fmt.Errorf("punch.sockets must not be negative")
	}
	if c.Sockets > 0 {
		s.sockets = c.Sockets
		if s.sockets > maxPunchSockets {
			s.sockets = maxPunchSockets
		}
	}

	if c.SocketWindow < 0 {
		return punchSettings{}, fmt.Errorf("punch.socketWindow must not be negative")
	}
	if c.SocketWindow > 0 {
		s.socketWindow = c.SocketWindow
	}
	if s.socketWindow > maxPunchSocketWindow {
		return punchSettings{}, fmt.Errorf("punch.socketWindow (%s) must be at most %s", s.socketWindow, maxPunchSocketWindow)
	}

	if c.SeedGrace < 0 {
		return punchSettings{}, fmt.Errorf("punch.seedGrace must not be negative")
	}
	if c.SeedGrace > 0 {
		s.seedGrace = c.SeedGrace
	}
	return s, nil
}
