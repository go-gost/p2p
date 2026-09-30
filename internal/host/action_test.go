package host

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/go-gost/p2p"
)

// newActionTestHost builds a stub-mode host (no relay) with the given logger.
// The action line is written at seam entry, before any engine check, so a stub
// host is enough to observe it and no relay is needed.
func newActionTestHost(t *testing.T, log *slog.Logger) *Host {
	t.Helper()
	h, err := New(&p2p.Config{}, WithLogger(log))
	if err != nil {
		t.Fatalf("new host: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// actionLines counts the action fields in a captured log, so a test can tell
// "logged once" from "logged at all".
func actionLines(s string) int { return strings.Count(s, "action=") }

// TestSeamLogsTheActionFromContext: a seam call made with an action-carrying
// ctx names it exactly once, and the same call without one logs no action field
// at all (never an empty action=).
func TestSeamLogsTheActionFromContext(t *testing.T) {
	var buf bytes.Buffer
	h := newActionTestHost(t, slog.New(slog.NewTextHandler(&buf, nil)))

	// Listen on a stub host errors (no relay). That is fine: the line is written
	// at entry and what this test reads is the log, not the result.
	_, _ = h.ListenContext(WithAction(context.Background(), "ab12cd34"))
	if got := buf.String(); !strings.Contains(got, "action=ab12cd34") {
		t.Fatalf("ListenContext log = %q, want it to name the action", got)
	}
	if n := actionLines(buf.String()); n != 1 {
		t.Fatalf("action logged %d times, want exactly 1 (%q)", n, buf.String())
	}

	// The plain method is untouched: a caller with no action adds no field.
	buf.Reset()
	_, _ = h.Listen()
	if got := buf.String(); actionLines(got) != 0 {
		t.Fatalf("plain Listen log = %q, want no action field", got)
	}
}

// TestWarmAndPunchLogTheAction: the other ctx-carrying seam calls name the
// action too, and both WithAction's empty id and the plain methods stay silent.
func TestWarmAndPunchLogTheAction(t *testing.T) {
	var buf bytes.Buffer
	h := newActionTestHost(t, slog.New(slog.NewTextHandler(&buf, nil)))

	// Stub mode returns from warm before it parses the peer key, so any string
	// is a valid argument here.
	_ = h.WarmContext(WithAction(context.Background(), "deadbeef"), "peer")
	if got := buf.String(); !strings.Contains(got, "action=deadbeef") {
		t.Fatalf("WarmContext log = %q, want it to name the action", got)
	}

	buf.Reset()
	_ = h.PunchContext(WithAction(context.Background(), "cafebabe"), "peer")
	if got := buf.String(); !strings.Contains(got, "action=cafebabe") {
		t.Fatalf("PunchContext log = %q, want it to name the action", got)
	}

	// No action, and an empty id (nothing to name): neither logs a field.
	buf.Reset()
	_ = h.WarmContext(context.Background(), "peer")
	_ = h.PunchContext(WithAction(context.Background(), ""), "peer")
	_ = h.Warm("peer")
	_ = h.Punch("peer")
	if got := buf.String(); actionLines(got) != 0 {
		t.Fatalf("plain/empty-id calls log = %q, want no action field", got)
	}
}

// TestDialLogsTheAction: Dial already took a ctx, so it names the action too. A
// cancelled ctx makes the call return after the log and before any goroutine
// starts, which keeps this deterministic (and race-clean).
func TestDialLogsTheAction(t *testing.T) {
	var buf bytes.Buffer
	h := newActionTestHost(t, slog.New(slog.NewTextHandler(&buf, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Dial(WithAction(ctx, "0f0f0f0f"), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("Dial with a cancelled ctx = nil error, want a failure")
	}
	if got := buf.String(); !strings.Contains(got, "action=0f0f0f0f") {
		t.Fatalf("Dial log = %q, want it to name the action", got)
	}
}
