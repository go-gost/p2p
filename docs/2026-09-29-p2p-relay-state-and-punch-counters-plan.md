# Relay state and per-peer punch counters — design and plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a relay outage visible through `Status`, and make hole-punch churn attributable to a single peer.

**Architecture:** No new state machines. The engine already maintains `client *derpclient.Client` and `dialErr`, and its 5-second `reconnect()` loop already computes `wasDown := e.client == nil`. Two additions: expose that state through `Status`, and add three per-peer atomic counters to `directConn` (`attempts` / `ups` / `drops`).

**Tech Stack:** Go 1.26. `p2p` (root) is the stdlib-only contracts package; `internal/host` holds the engine; `net/http/httptest` is not needed — `internal/host/server_test.go` already builds an `engine` literal and calls `status()`.

**Commits:** the repo owner asks for commits explicitly. Each "Commit" step is a checkpoint — run it when asked, do not commit on your own initiative.

**No version bump:** this plan does not touch any consumer's `go.mod`. `go.work` resolves `p2p` and `wisper` from the local tree, so local builds and tests exercise these changes without a tag. Publishing the tag and bumping the dependent module is the owner's separate step.

---

## Why (measured, not assumed)

A loopback probe against a real `derper` (2026-09-29, four phases, 37 s):

| Moment | `PeerTransports` | direct/derp | punch |
|---|---|---|---|
| relay up, no traffic, t=0–3 s | `peer=derp` | 0/1 | 0/0 |
| t=4 s (punch completed) | `peer=direct` | 1/0 | 1/1 |
| one stream through the tunnel | `peer=direct` | 1/0 | 1/1 |
| **12 s after the derper was killed** | `peer=direct` — unchanged | 1/0 — unchanged | 1/1 — unchanged |
| 15 s after the relay came back | unchanged | unchanged | unchanged |

Two conclusions shaped this change:

1. **A relay outage is invisible in `Status`.** Every gauge and counter stayed put for 12 s+ while the relay was dead; the only trace was a `derp dial ... connection refused` log line every 5 s. Cause: `Status` has no relay-connectivity field, and a hole-punched session is independent of the DERP transport (kept in `e.directs`, separate from the relay) — so "relay dead, direct alive" reads as perfectly healthy.
2. **`PunchAttempts` is process-wide**, so it cannot say *which* peer is re-punching. Byte counting is per peer already (`PeerStats`), and so is the transport gauge — the punch history is the outlier.

The `derp → direct` transition, by contrast, **is** visible at 1-second sampling (the punch took ~4 s). No change is needed for that.

## What the new fields are for

- `RelayConnected` / `RelayError` — turns "the relay is down" from a log line into a first-class, diffable state. A consumer can then report *relay disconnected* / *relay restored*.
- `PeerPunch.Drops` — the literal disconnect count: a live direct session ended. This is the signal that makes "direct sessions keep dying" visible per peer, without depending on catching a sub-second window.
- `PeerPunch.Attempts` / `Ups` — the context that distinguishes "died and rebuilt" (drops and ups both rising) from "cannot punch at all" (attempts rising, ups flat — the symmetric-NAT case).

## Where the counters attach

`detachSessionLocked` is the single choke point for a direct session's death: both callers go through it — `markDead` (the accept loop ended) and `session()` (the *opening* side noticing a dead session on its next use). Counting a drop only in `markDead` would miss the opening side. Its `repunch == true` return means exactly "a live (`directUp`) session ended", and it runs under `dc.mu`, so the counters must be atomics (`atomic.Int64`) rather than mutex-guarded fields — `internal/host` is careful about lock ordering (`dc.mu` is never taken while holding `e.mu`), and atomics sidestep it entirely.

| Event | Where | Counter |
|---|---|---|
| a punch round starts | `punch()`, beside `e.stats.punchAttempts.Add(1)` | `dc.attempts` |
| a direct session comes up | `markUp()`, beside `e.stats.punchSuccess.Add(1)` | `dc.ups` |
| a live direct session ends | `detachSessionLocked()`, in the `state == directUp` branch | `dc.drops` |

## Contract shape

In `status.go` (root package, stdlib only):

```go
// PeerPunch is one peer's hole-punch history.
type PeerPunch struct {
	Attempts int64 // punch rounds started for this peer
	Ups      int64 // rounds that reached a live direct session
	Drops    int64 // live direct sessions that ended (and re-punched)
}
```

`Status` gains `RelayConnected bool`, `RelayError string`, and `PeerPunches map[string]PeerPunch`.

## File structure

| File | Change | Responsibility |
|---|---|---|
| `status.go` | modify | `PeerPunch`, and the three new `Status` fields |
| `internal/host/direct.go` | modify | `directConn`'s three atomics, bumped at the three sites; `punchCounts()` |
| `internal/host/direct_test.go` | modify | drop/up counting, including the non-owning case |
| `internal/host/engine.go` | modify | `relayState()`, `peerPunches()` |
| `internal/host/engine_test.go` | modify | `relayState()` across its three states |
| `internal/host/server.go` | modify | fill the new fields in `status()` |
| `internal/host/server_test.go` | modify | stub mode, and the new fields reaching the reply |
| `CLAUDE.md` | modify | document the new `Status` fields where `Status` is described |

---

## Task 1: The contract fields

**Files:**
- Modify: `status.go`

- [ ] **Step 1: Add the type and the fields**

In `status.go`, add the import-free type above `Status`:

```go
// PeerPunch is one peer's hole-punch history. The process-wide
// PunchAttempts/PunchSuccess cannot say which peer is re-punching, which is the
// question a direct session that keeps dying raises.
type PeerPunch struct {
	Attempts int64 // punch rounds started for this peer
	Ups      int64 // rounds that reached a live direct session
	Drops    int64 // live direct sessions that ended (and re-punched)
}
```

Inside `Status`, after `PeerTransports`:

```go
	// RelayConnected reports whether the relay transport holds a live
	// connection, and RelayError the last dial failure (empty while connected).
	//
	// None of the fields above can show a relay outage: a live hole-punched
	// session keeps every gauge and counter healthy while the relay is
	// unreachable, and the direct session is independent of the DERP transport.
	//
	// In-process only, like PeerTransports: the gRPC transport's proto is
	// frozen, so plugin clients see neither.
	RelayConnected bool
	RelayError     string

	// PeerPunches is each connected peer's own punch history, keyed by base64
	// public key. A peer that has never attempted a direct path is absent.
	// In-process only, like PeerTransports.
	PeerPunches map[string]PeerPunch
```

- [ ] **Step 2: Verify the contracts package still builds standalone**

Run: `GOWORK=off go build ./... && GOWORK=off go vet ./...`
Expected: no output. (The root package must stay stdlib-only; `atomic`-free data types add no dependency.)

- [ ] **Step 3: Run the dependency guard**

Run: `go test -count=1 -run TestRootHasNoExternalDependencies .`
Expected: PASS — the root package still imports nothing outside the standard library.

- [ ] **Step 4: Commit**

```bash
git add status.go
git commit -m "contracts: report relay state and per-peer punch history in Status"
```

---

## Task 2: Per-peer counters on the direct connection

**Files:**
- Modify: `internal/host/direct.go`
- Test: `internal/host/direct_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/host/direct_test.go`:

```go
// A live direct session ending must be counted once, and only when the session
// actually owned the state: a round already rebuilding is not a new drop.
func TestDetachSessionCountsDropOnce(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}, sess: newTestSess(t), state: directUp}

	sock, repunch := dc.detachSessionLocked(dc.sess)
	if !repunch {
		t.Fatal("repunch = false, want true for a session that owned directUp")
	}
	if sock == nil {
		t.Error("socket = nil, want the session's socket")
	}
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d, want 1", got)
	}

	// A second detach has nothing to detach: no second drop.
	if _, repunch := dc.detachSessionLocked(dc.sess); repunch {
		t.Error("a second detach reported a re-punch")
	}
	if got := dc.drops.Load(); got != 1 {
		t.Errorf("drops = %d after a no-op detach, want 1", got)
	}
}

// A session that did not own the state (a round is already rebuilding) is not
// this side's drop to count: it returns repunch=false.
func TestDetachSessionIgnoresNonOwningState(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	sess := newTestSess(t)
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}, sess: sess, state: directAttempting}

	if _, repunch := dc.detachSessionLocked(sess); repunch {
		t.Error("repunch = true for a session that did not own directUp")
	}
	if got := dc.drops.Load(); got != 0 {
		t.Errorf("drops = %d, want 0", got)
	}
}

// A session coming up counts as an up.
func TestMarkUpCountsUps(t *testing.T) {
	e := &engine{directs: make(map[derpclient.PublicKey]*directConn)}
	dc := &directConn{e: e, peer: derpclient.PublicKey{1}}

	dc.markUp(newTestSess(t), nil, netip.AddrPort{})

	if got := dc.ups.Load(); got != 1 {
		t.Errorf("ups = %d, want 1", got)
	}
	if dc.stateOf() != directUp {
		t.Errorf("state = %v, want directUp", dc.stateOf())
	}
}
```

`netip` needs `"net/netip"` in the test file's imports; `derpclient` and `testing` are already there (see `server_test.go`'s package-level imports — this file is the same package).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CGO_ENABLED=1 go test -race -count=1 -run 'TestDetachSession|TestMarkUp' ./internal/host/ -v`
Expected: FAIL — `dc.drops undefined`, `dc.ups undefined`.

- [ ] **Step 3: Add the counters and the accessor**

In `internal/host/direct.go`, in the `directConn` struct, after the existing `failed bool` field:

```go
	// This peer's punch history, reported through Status.PeerPunches. Atomics:
	// detachSessionLocked runs under dc.mu, and taking a second lock there would
	// put it in the engine's lock order for no reason.
	attempts atomic.Int64 // punch rounds started
	ups      atomic.Int64 // rounds that reached a live direct session
	drops    atomic.Int64 // live direct sessions that ended
```

Add `"sync/atomic"` to the file's imports.

Add the accessor next to `live()`:

```go
// punchCounts snapshots this peer's punch history. The counters are atomics, so
// this takes no lock: a status query must not queue behind a punch round.
func (dc *directConn) punchCounts() p2p.PeerPunch {
	return p2p.PeerPunch{
		Attempts: dc.attempts.Load(),
		Ups:      dc.ups.Load(),
		Drops:    dc.drops.Load(),
	}
}
```

- [ ] **Step 4: Bump them at the three sites**

In `punch()`, beside the existing `e.stats.punchAttempts.Add(1)`:

```go
	e.stats.punchAttempts.Add(1)
	dc.attempts.Add(1)
```

In `markUp()`, beside the existing `dc.e.stats.punchSuccess.Add(1)`:

```go
	dc.e.stats.punchSuccess.Add(1)
	dc.ups.Add(1)
```

In `detachSessionLocked()`, in the branch that schedules the re-punch:

```go
	if dc.state == directUp {
		dc.state = directNone
		dc.drops.Add(1)
		return sock, true
	}
```

The drop is counted even when the caller then skips the re-punch (`dropIfGone`, or an engine close): the session *did* end, and that is what the counter reports.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `CGO_ENABLED=1 go test -race -count=1 ./internal/host/ -v`
Expected: PASS, including the existing direct/engine suites.

- [ ] **Step 6: Commit**

```bash
git add internal/host/direct.go internal/host/direct_test.go
git commit -m "host: count each peer's punch rounds, ups and drops"
```

---

## Task 3: Engine accessors

**Files:**
- Modify: `internal/host/engine.go`
- Test: `internal/host/engine_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/host/engine_test.go`:

```go
// relayState must report the engine's own relay connection: the three states a
// status consumer has to tell apart.
func TestRelayState(t *testing.T) {
	// Never dialed.
	e := &engine{}
	if up, msg := e.relayState(); up || msg != "" {
		t.Errorf("fresh engine: up=%v msg=%q, want false/\"\"", up, msg)
	}

	// Connected.
	e.client = &derpclient.Client{}
	if up, msg := e.relayState(); !up || msg != "" {
		t.Errorf("connected: up=%v msg=%q, want true/\"\"", up, msg)
	}

	// Down, with the reason a user can act on.
	e.client = nil
	e.dialErr = errors.New("dial tcp 127.0.0.1:443: connect: connection refused")
	up, msg := e.relayState()
	if up {
		t.Error("up = true with no client")
	}
	if !strings.Contains(msg, "connection refused") {
		t.Errorf("msg = %q, want the dial failure", msg)
	}
}
```

`errors` and `strings` join the file's imports if absent.

- [ ] **Step 2: Run the test to verify it fails**

Run: `CGO_ENABLED=1 go test -race -count=1 -run TestRelayState ./internal/host/ -v`
Expected: FAIL — `e.relayState undefined`.

- [ ] **Step 3: Implement the accessors**

In `internal/host/engine.go`, after `peerTransports()`:

```go
// relayState reports whether the relay holds a live connection, and the last
// dial failure. Status exposes it because no other field can show a relay
// outage: a live direct session keeps every gauge and counter healthy while the
// relay is unreachable.
func (e *engine) relayState() (connected bool, lastErr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.dialErr != nil {
		lastErr = e.dialErr.Error()
	}
	return e.client != nil, lastErr
}

// peerPunches returns each connected peer's own punch history, keyed by base64
// public key. Empty when nothing has a direct connection, so a stub-mode or
// relay-only host reports nothing rather than an empty map.
func (e *engine) peerPunches() map[string]p2p.PeerPunch {
	e.mu.Lock()
	directs := make([]*directConn, 0, len(e.directs))
	for _, dc := range e.directs {
		directs = append(directs, dc)
	}
	e.mu.Unlock()

	if len(directs) == 0 {
		return nil
	}
	out := make(map[string]p2p.PeerPunch, len(directs))
	for _, dc := range directs {
		out[keyName(dc.peer)] = dc.punchCounts()
	}
	return out
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `CGO_ENABLED=1 go test -race -count=1 ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/engine.go internal/host/engine_test.go
git commit -m "host: expose the relay's connection state and per-peer punch history"
```

---

## Task 4: Reach the reply

**Files:**
- Modify: `internal/host/server.go`
- Test: `internal/host/server_test.go`

- [ ] **Step 1: Write the failing test**

Extend `TestStatusReportsTransportStats` in `internal/host/server_test.go` (it already builds the engine, the direct peer and the relay peer) — after the existing counter assertions, add:

```go
	// The relay's own state, and the direct peer's punch history.
	if st.RelayConnected {
		t.Error("RelayConnected = true, want false for an engine with no client")
	}
	if got, ok := st.PeerPunches[base64.RawURLEncoding.EncodeToString(peerDirect[:])]; !ok {
		t.Errorf("PeerPunches has no entry for the direct peer: %+v", st.PeerPunches)
	} else if got.Attempts != 4 || got.Ups != 2 || got.Drops != 1 {
		t.Errorf("PeerPunch = %+v, want attempts=4 ups=2 drops=1", got)
	}
```

and set the counters on `dc` where the test builds it:

```go
	dc := &directConn{e: e, peer: peerDirect, sess: newTestSess(t), state: directUp}
	dc.attempts.Store(4)
	dc.ups.Store(2)
	dc.drops.Store(1)
```

Also extend `TestStatusNoEngine` (stub mode) with:

```go
	if st.RelayConnected || st.PeerPunches != nil {
		t.Errorf("stub-mode relay/peer fields = %v/%v, want false/nil", st.RelayConnected, st.PeerPunches)
	}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `CGO_ENABLED=1 go test -race -count=1 -run TestStatus ./internal/host/ -v`
Expected: FAIL — `PeerPunches` is empty and `RelayConnected` is not set by `status()`.

- [ ] **Step 3: Fill them**

In `internal/host/server.go`'s `status()`, inside the `if s.engine != nil` block, before the existing `PeerTransports` line:

```go
		st.RelayConnected, st.RelayError = s.engine.relayState()
		st.PeerTransports = s.engine.peerTransports()
		st.PeerPunches = s.engine.peerPunches()
```

(Replace the existing single `st.PeerTransports = ...` line with this block; the loop that counts `DirectPeers`/`DerpPeers` from `PeerTransports` stays as it is.)

- [ ] **Step 4: Run the tests to verify they pass**

Run: `CGO_ENABLED=1 go test -race -count=1 ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/host/server.go internal/host/server_test.go
git commit -m "host: report relay state and per-peer punches through Status"
```

---

## Task 5: Keep the documentation honest

**Files:**
- Modify: `CLAUDE.md`

The repository's own doc describes `Status` field by field in the "Control plane" section and in the `Status` bullet. Leaving it stale is how the "in-process only, proto frozen" note got its value in the first place.

- [ ] **Step 1: Update the `Status` description**

`CLAUDE.md` line ~82 is a single long `Status` bullet. Insert the new fields between the counters and `and \`PeerTransports\`` — the existing text reads `…cumulative counters \`punch_attempts\`/\`punch_success\`/\`streams_direct\`/\`streams_derp\`, and \`PeerTransports\` — one value per connected base64 peer key…`. Make it read:

```
…cumulative counters `punch_attempts`/`punch_success`/`streams_direct`/
`streams_derp`, `relay_connected`/`relay_error` (the relay transport's own
liveness, which no other field can show: a live hole-punched session keeps
every gauge healthy while the relay is unreachable) and `peer_punches` (each
connected peer's `attempts`/`ups`/`drops`, where `drops` is the literal count
of direct sessions that ended — the per-peer form of the process-wide
`punch_attempts`), and `PeerTransports` — one value per connected base64 peer key…
```

Then extend the trailing parenthetical that already scopes `PeerTransports` to in-process (`(in-process only: the proto has no field for it, so the gRPC transport carries the aggregate gauges)`) so it covers the new fields too:

```
(in-process only: the proto has no field for them, so the gRPC transport
carries the aggregate gauges)
```

- [ ] **Step 2: Verify the docs build step**

Run: `grep -n "relay_connected\|peer_punches" CLAUDE.md`
Expected: both names appear in the updated bullet.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: describe the relay state and per-peer punch fields"
```

---

## Task 6: Full verification

- [ ] **Step 1: Format, build and vet the module**

Run: `gofmt -l . && go build ./... && go vet ./...`
Expected: `gofmt -l` prints nothing; the build and vet print nothing.

- [ ] **Step 2: Confirm the standalone build still passes**

Run: `GOWORK=off go build ./...`
Expected: no output. The contracts package's stdlib-only promise is guarded by `deps_test.go`; this is the module-level counterpart.

- [ ] **Step 3: Run the tests per package with the race detector**

Run: `CGO_ENABLED=1 go test -race -count=1 ./internal/host/ ./internal/stun/ ./internal/derpclient/ ./endpoint/ ./grpc/`
Expected: `ok` for each. Run the packages by name: a wildcard `go test ./...` is known to hang in this workspace.

`TestSeedHandshake` flakes about 10% of the time with `sendmmsg: operation not permitted` (a sandbox syscall denial, present on HEAD too) — re-run rather than bisecting.

- [ ] **Step 4: Confirm the new fields are observable end to end**

Re-run the throwaway probe kept at `wisper/tunnel/probe_events_test.go` (build tag `p2ppoc`), which kills the relay mid-run:

```bash
cd /config/workspace/go-gost/wisper
CGO_ENABLED=1 go test -tags p2ppoc -run TestProbeEventSignals -v -timeout 8m ./tunnel/
```

Then replace the probe's `sample()` body in `tunnel/probe_events_test.go` with this version, which prints the new fields:

```go
	sample := func(label string) {
		st := wtunnel.P2PHostStatus()
		var punches []string
		for k, v := range st.PeerPunches {
			punches = append(punches, fmt.Sprintf("%s=%+v", k[:8], v))
		}
		sort.Strings(punches)
		t.Logf("%-24s running=%v relay=%v err=%q peers=[%s] punches=[%s] direct=%d derp=%d punch=%d/%d streams=%d/%d",
			label, wtunnel.P2PHostRunning(), st.RelayConnected, st.RelayError,
			peers(st), strings.Join(punches, ","),
			st.DirectPeers, st.DerpPeers, st.PunchSuccess, st.PunchAttempts,
			st.StreamsDirect, st.StreamsDerp)
	}
```

Expected (these are the values actually observed on 2026-09-29): on killing the derper, `relay=false` **with an empty `err`** on the very next sample, and the reason `err="... connection refused"` arriving as a *second* change up to 5 s later — the engine drops the client at once but only records `dialErr` on its next redial tick. On restarting the derper, `relay=true` again within ~5 s. Pre-change, **nothing at all changed for the whole 12 s outage**. `punches` stays at `attempts=1 ups=1 drops=0` in this scenario: the direct session survived the relay outage, which is precisely the behaviour that made the outage invisible.

- [ ] **Step 5: Report**

Record what was observed, quoting the probe's phase-3 lines. If the relay fields did not flip, say so — do not report the change as verified.

---

## Out of scope

- Publishing a tag and bumping a consumer's `go.mod` (the owner's step; `go.work` covers local work).
- The 18-second direct-session churn: it does not reproduce on loopback (a plain punch stayed up for the whole probe) and remains a real-LAN/device question. These counters are what will make it measurable there.
