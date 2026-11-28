# p2p Cone ↔ Random Punch Fallback Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in IPv4 punch fallback for the measured asymmetric NAT pair — a Cone side sprays random ports, a Random-symmetric side opens many sockets — so wisper can get a direct path on cellular instead of staying on the relay.

**Architecture:** The normal punch stays unchanged. After `AfterRounds` seed failures, if both peers advertise `capsSpray`, the Cone side runs a multi-target seed from its existing punch socket toward the peer's public IPv4 random ports, while the Random side runs one seed per socket across `Sockets` sockets. The first completing pair is installed through the existing `markUp`/`directUnderlay` path; all other sockets close. No new transport, no wire-format break, no relay change.

**Tech Stack:** Go 1.27, `p2p` module, stdlib only (existing kcp-go/smux/QUIC stack unchanged).

**Spec:** `p2p/docs/superpowers/specs/2026-11-28-p2p-cone-random-punch-design.md`

## Global Constraints

- Code comments in English only.
- `Punch.Mode` empty or `off` must reproduce today's behavior exactly; no new traffic, no new caps bits, no behavior change for old peers.
- New caps bit is `capsSpray uint8 = 1 << 4` (bit 3 is already `capsQUIC`).
- IPv4 only. Do not change IPv6, DERP/WSS, or KCP/QUIC.
- Caps: `sprayPorts` clamped to 2048, `sockets` clamped to 512, `sprayEvery >= 1s`, `socketWindow <= 60s`.
- Fallback is opt-in, runs only after a failed normal seed round, only toward an authenticated peer's public IPv4, and stops on success.
- No new module dependency.
- Tests run from `p2p/` with `GOWORK=off`:
  `GOWORK=off go test ./internal/host -run <Test> -count=1`
- Commit after every task. After the code commit, fill the task's Implementation record in this file (use `git rev-parse HEAD` for the code commit), `git add` the plan, and commit `docs(p2p): record task N`. Only commit; never push.
- The wisper wiring (settings/API/host config) is a separate follow-up plan after the p2p tag; this plan ends with a manual field verification.

## Review Focus

- The first-completing side must keep echoing the peer's token for `SeedGrace`; otherwise the peer's seed probe is later consumed as data by the installed underlay.
- `fallbackReady` must arm only after **seed** failures, never after control-plane misses (`no peer candidates`) or "no local candidates".
- The 30s normal `backoff` must not run between the last normal failure and the first fallback round; use a 500ms retry.
- Caps bit 4 must not collide with `capsQUIC` (bit 3); old peers must never receive spray and must never arm the fallback.
- The spray socket must be the same socket that produced the advertised public p3; a new socket would advertise a different mapping than it sprays from.
- `collectV4` failure means no public IPv4 for the spray side to target (or no p3 for the sockets side to dial); skip the fallback rather than spraying an unknown address.
- The winning socket must be the only one installed; losing sockets must close before `markUp` touches the winner.
- 1000 ports every 2s and 150 sockets are bounded; a failed fallback must back off, not loop at packet rate.

---

### Task 1: Punch configuration and normalization

**Files:**
- Modify: `p2p/config.go` (add `Punch *PunchConfig` to `Config`, define `PunchConfig`)
- Create: `p2p/internal/host/punch.go` (`punchSettings`, `resolvePunch`)
- Modify: `p2p/internal/host/host.go` (set `h.engine.punch`)
- Modify: `p2p/cmd/p2p/main.go` (flags)
- Test: `p2p/internal/host/punch_test.go`
- Test: `p2p/cmd/p2p/config_test.go`

**Interfaces:**
- `type PunchConfig struct { Mode string; AfterRounds int; SprayPorts int; SprayEvery time.Duration; Sockets int; SocketWindow time.Duration; SeedGrace time.Duration }` (yaml tags `mode`, `afterRounds`, `sprayPorts`, `sprayEvery`, `sockets`, `socketWindow`, `seedGrace`)
- `type punchSettings struct { mode string; afterRounds, sprayPorts, sockets int; sprayEvery, socketWindow, seedGrace time.Duration }`
- `func resolvePunch(c *p2p.PunchConfig) (punchSettings, error)`
- `engine.punch punchSettings`

- [ ] **Step 1: Write the failing test**

`p2p/internal/host/punch_test.go`:
```go
func TestResolvePunchDefaults(t *testing.T) {
    got, err := resolvePunch(nil)
    if err != nil { t.Fatal(err) }
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
    if err != nil { t.Fatal(err) }
    if got.sprayPorts != 2048 || got.sockets != 512 { t.Fatalf("clamp = %+v", got) }
    for _, bad := range []*p2p.PunchConfig{
        {Mode: "spray", SprayEvery: 100 * time.Millisecond},
        {Mode: "sockets", SocketWindow: 61 * time.Second},
    } {
        if _, err := resolvePunch(bad); err == nil { t.Fatalf("want error for %+v", bad) }
    }
}
```
`p2p/cmd/p2p/config_test.go`: add `TestPunchConfigRoundTrip` with a YAML file containing:
```yaml
punch:
  mode: spray
  afterRounds: 2
  sprayPorts: 512
  sprayEvery: 3s
  sockets: 64
  socketWindow: 15s
  seedGrace: 750ms
```
assert every field after load.

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestResolvePunch' -count=1`
Expected: FAIL — `resolvePunch` undefined / `p2p.PunchConfig` undefined.

- [ ] **Step 3: Implement the config and the resolver**

- `p2p/config.go`: add `Punch *PunchConfig` with a doc comment explaining the two roles; `PunchConfig` fields as above with yaml tags.
- `p2p/internal/host/punch.go`: `resolvePunch` applies defaults, validates mode in `""`, `off`, `spray`, `sockets`, clamps, rejects `SprayEvery < 1s`/`SocketWindow > 60s`/negative values. `off` normalizes to `""`.
- `p2p/internal/host/engine.go`: add `punch punchSettings` to `engine`.
- `p2p/internal/host/host.go`: after `h.engine.direct = *cfg.Direct`, call `resolvePunch(cfg.Punch)`, return the error, assign `h.engine.punch`.
- `p2p/cmd/p2p/main.go`: add flags `--punch-mode`, `--punch-after-rounds`, `--punch-spray-ports`, `--punch-spray-every`, `--punch-sockets`, `--punch-socket-window`, `--punch-seed-grace`; override `cfg.Punch` only when `set[...]`.

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestResolvePunch' -count=1`
`GOWORK=off go test ./cmd/p2p -run 'TestPunchConfigRoundTrip' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add config.go internal/host/punch.go internal/host/engine.go internal/host/host.go \
  internal/host/punch_test.go cmd/p2p/main.go cmd/p2p/config_test.go \
  docs/superpowers/specs/2026-11-28-p2p-cone-random-punch-design.md \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): add punch fallback configuration"
```

**Implementation record**

- Date/status: 2026-11-28 — complete.
- Repo/commit: `p2p` (worktree `/root/code/go-gost/p2p/.worktrees/p2p-cone-random`), branch `feat/p2p-cone-random`; code commit `b8d93725e20414f022ca69f3803373b7c32a2e4c` (`b8d9372`). This record is added in the follow-up `docs(p2p): record task 1` commit.
- Files changed: `config.go` (`Config.Punch`, `PunchConfig`), `internal/host/punch.go` (`punchSettings`, `resolvePunch`, defaults/limits), `internal/host/punch_test.go` (3 resolver tests), `internal/host/engine.go` (`engine.punch`), `internal/host/host.go` (`host.New` resolves and assigns it), `cmd/p2p/main.go` (7 `--punch-*` flags with per-flag overrides), `cmd/p2p/config_test.go` (`TestPunchConfigRoundTrip`). No dependency changes.
- Tests/commands and results:
  - RED before implementation: `GOWORK=off go test ./internal/host -run 'TestResolvePunch' -count=1` → FAIL (build failed: `undefined: resolvePunch`, `undefined: p2p.PunchConfig`); `GOWORK=off go test ./cmd/p2p -run 'TestPunchConfigRoundTrip' -count=1` → FAIL (build failed: `c.Punch undefined (type *config has no field or method Punch)`).
  - GREEN after implementation: the same two commands → `ok github.com/go-gost/p2p/internal/host 0.004s` and `ok github.com/go-gost/p2p/cmd/p2p 0.005s` (final rerun).
  - Additional checks: `GOWORK=off go test ./cmd/p2p -count=1` → `ok github.com/go-gost/p2p/cmd/p2p 0.009s`; `GOWORK=off go build ./...` → PASS (no output); `git diff --check` → clean. The full `internal/host` suite was deliberately not run (known flaky; brief scopes verification to the focused tests).
  - Regression RED before fix: `GOWORK=off go test ./internal/host -run 'TestResolvePunchOffSkipsValidation' -count=1` → FAIL: both `off` and `empty` subtests reported `punch.afterRounds must not be negative` from the numeric validation that ran despite the disabled mode.
  - GREEN after fix: `GOWORK=off go test ./internal/host -run 'TestResolvePunch' -count=1` → `ok github.com/go-gost/p2p/internal/host 0.004s`; `GOWORK=off go test ./cmd/p2p -run 'TestPunchConfigRoundTrip' -count=1` → `ok github.com/go-gost/p2p/cmd/p2p 0.007s`; `GOWORK=off go build ./...` → PASS (no output).
- Review findings and fixes: Important (reviewer): `punch.mode: ""`/`off` was accepted by the mode switch but all numeric validation still ran, so `punch: {mode: off, sprayEvery: 500ms}` or `--punch-spray-every 500ms` without `--punch-mode spray` made `host.New` fail, violating the "disabled reproduces today's behavior exactly" constraint. Fixed by returning the already-default `s` immediately after the mode switch when `s.mode == ""` (both explicit `off` and empty), before any numeric validation/clamping; full validation remains for `spray`/`sockets`. Added `TestResolvePunchOffSkipsValidation` covering `off` and `""` with invalid fallback knobs. Self-review from the original task: reordered `punchSettings` fields to match the plan's interface; corrected the seven flag help strings from "keeps the config/default" to "uses the built-in default" because an explicit `0` overrides the file value. Re-ran both focused tests and the build after these edits; no unrelated files changed.
- Deferred items/limitations: this task only stores and normalizes config — no caps bit, spray/socket engines, socket lifecycle, status/doctor fields or e2e (Tasks 2–8). The verbatim brief tests cover defaults, unknown mode, clamp and two invalid durations; negative-value rejection and `off` normalization are implemented per plan but get no direct assertion until later test work. `engine.punch` is not yet read by any code path.

---

### Task 2: Spray capability bit and engine wiring

**Files:**
- Modify: `p2p/internal/host/caps.go` (`capsSpray`)
- Modify: `p2p/internal/host/direct.go` (`capNames`, `usesFallback` helper if needed)
- Modify: `p2p/internal/host/engine.go` (`caps()`)
- Test: `p2p/internal/host/caps_test.go`
- Test: `p2p/internal/host/punch_test.go` (engine wiring)

**Interfaces:**
- `const capsSpray uint8 = 1 << 4`
- `func (e *engine) sprayEnabled() bool` — true when `e.punch.mode` is `spray` or `sockets`.
- `capNames(bits uint8) []string` includes `"spray"`.

- [ ] **Step 1: Write the failing test**

```go
func TestCapsSprayBit(t *testing.T) {
    if capsSpray == capsQUIC { t.Fatal("capsSpray collides with capsQUIC") }
    e := &engine{punch: punchSettings{mode: "spray"}}
    if e.caps().Bits&capsSpray == 0 { t.Fatal("spray mode did not advertise capsSpray") }
    e.punch = punchSettings{}
    if e.caps().Bits&capsSpray != 0 { t.Fatal("empty punch mode advertised capsSpray") }
}

func TestCapNamesIncludesSpray(t *testing.T) {
    if got := capNames(capsSpray); len(got) != 1 || got[0] != "spray" {
        t.Fatalf("capNames = %v", got)
    }
}
```
Also add a test that `decodeCaps([]byte{capsSpray})` returns the bit, and that `dc.addCaps(capsInfo{Bits: capsSpray})` makes `dc.supports(capsSpray)` true.

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestCapsSpray|TestCapNamesIncludesSpray' -count=1`
Expected: FAIL — `capsSpray` undefined / `spray` missing.

- [ ] **Step 3: Implement**

- Add `capsSpray = 1 << 4` in `caps.go` with a comment naming the roles.
- Add `sprayEnabled()` in `direct.go` or `punch.go`.
- In `engine.caps()`, `if e.sprayEnabled() { info.Bits |= capsSpray }`.
- In `capNames`, append `"spray"` for the bit.

- [ ] **Step 4: Run tests to verify they pass**

Run: `GOWORK=off go test ./internal/host -run 'TestCapsSpray|TestCapNamesIncludesSpray|TestCaps' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add internal/host/caps.go internal/host/direct.go internal/host/engine.go \
  internal/host/caps_test.go internal/host/punch_test.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): advertise spray capability"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 3: Multi-target seed handshake with responder grace

**Files:**
- Create: `p2p/internal/host/seedplan.go`
- Modify: `p2p/internal/host/direct.go` (`seedHandshakeUDPToken` becomes a wrapper)
- Test: `p2p/internal/host/seedplan_test.go`

**Interfaces:**
- `type seedPlan struct { Peer netip.AddrPort; Targets []netip.AddrPort; Retransmit time.Duration; SprayEvery time.Duration; Grace time.Duration }`
- `func seedHandshakePlan(sock *net.UDPConn, plan seedPlan, timeout time.Duration) (seedOutcome, error)`
- The existing `seedHandshakeUDPToken(sock, peer, timeout)` calls `seedHandshakePlan(sock, seedPlan{Peer: peer, Retransmit: seedRetransmit}, timeout)`.

Behavior pinned by tests:
- Sends its token to `Peer` every `Retransmit`; sends the whole `Targets` set every `SprayEvery` (first pass immediately).
- Only `seedProbeMagic` + full token packets count; no source filter.
- A peer probe updates `ProbeFrom`, becomes the retransmit target, and is echoed to its source.
- A packet carrying our own token is success (`Answer` = source); after success it keeps echoing peer probes for `Grace`, then returns.
- `Targets` may be empty; `SprayEvery` may be 0 (no set).

- [ ] **Step 1: Write the failing test**

`seedplan_test.go` using two `net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})` sockets:
```go
func TestSeedPlanSprayTargetsCompletes(t *testing.T) {
    // peer socket listens; the plan targets its port among a set of dead ports.
    // Run the peer's own seedHandshakePlan in a goroutine with Peer = our socket.
    // Both must return success; assert out.Answer == peer's address.
}

func TestSeedPlanResponderGraceEchoesAfterOwnSuccess(t *testing.T) {
    // A fake peer answers our token immediately, then waits 100ms and sends its
    // own token. Without Grace the call returns before that probe and the peer
    // never completes; with Grace = 300ms the peer completes.
}
```
Also add `TestSeedPlanLearnsUnexpectedSource` (a peer probe from a different port retargets retransmits).

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestSeedPlan' -count=1`
Expected: FAIL — `seedHandshakePlan` undefined.

- [ ] **Step 3: Implement**

Move the body of `seedHandshakeUDPToken` into `seedHandshakePlan`; add the target-set send schedule and the post-success grace loop; keep the existing token echo/learn semantics. The wrapper keeps the old signature and tests green.

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestSeedPlan|TestSeedHandshake|TestSeedAddress' -count=1`
Expected: PASS, including the pre-existing seed tests.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add internal/host/seedplan.go internal/host/seedplan_test.go internal/host/direct.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): seed handshake with target sets and echo grace"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 4: Arm the fallback after seed failures

**Files:**
- Modify: `p2p/internal/host/direct.go` (`directConn` fields, `fallbackReady`, `noteNormalSeedFailure`, `punch` failure path)
- Test: `p2p/internal/host/punch_test.go` (or `direct_test.go`)

**Interfaces:**
- `const fallbackRetry = 500 * time.Millisecond`
- `func (dc *directConn) fallbackReady(peerV4 []netip.AddrPort) bool`
- `func (dc *directConn) noteNormalSeedFailure()`
- `func (dc *directConn) noteFallbackSuccess()` / `noteFallbackFailure()`

Rules:
- `normalFailures` increments only on `winner < 0` (all seed attempts failed).
- `fallbackReady` requires `normalFailures >= e.punch.afterRounds`, `e.punch.mode` non-empty, `dc.supports(capsSpray)`, and a non-empty `peerV4` with a public address.
- On the seed-failure path: if `fallbackReady`, `dc.retry(fallbackRetry, true)`; else `dc.backoff()`.
- A successful normal round resets `normalFailures`.
- Once armed, a fallback failure calls `dc.backoff()`; the next round still sees `fallbackReady` and runs the fallback again.
- Control failures (`no peer candidates`, `no local candidates`, `no shared family`) must not increment `normalFailures`.

- [ ] **Step 1: Write the failing test**

```go
func TestFallbackArmsAfterSeedFailures(t *testing.T) {
    dc := newDirectConnForTest(t) // existing helper or a minimal directConn
    dc.e.punch = punchSettings{mode: "spray", afterRounds: 1}
    dc.addCaps(capsInfo{Bits: capsSpray})
    if dc.fallbackReady(publicV4) { t.Fatal("armed before any failure") }
    dc.noteNormalSeedFailure()
    if !dc.fallbackReady(publicV4) { t.Fatal("not armed after one seed failure") }
}

func TestFallbackNotArmedWithoutPeerCaps(t *testing.T) { /* same, no caps -> false */ }
func TestFallbackControlFailureDoesNotArm(t *testing.T) {
    // a round that ends with "no peer candidates" must leave normalFailures at 0.
}
func TestFallbackNotArmedWithoutPublicV4(t *testing.T) { /* local-only -> false */ }
func TestFallbackSeedSuccessResets(t *testing.T) { /* note success -> normalFailures 0 */ }
func TestFallbackRetryIsShort(t *testing.T) {
    // a failed normal round with fallbackReady schedules ~fallbackRetry, not backoffPeriod.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestFallback' -count=1`
Expected: FAIL — fields/functions undefined.

- [ ] **Step 3: Implement**

Add the fields/functions; wire the `winner < 0` branch in `punch()` and the normal success reset. Do not add the spray/sockets execution yet; `punchFallback` may return a sentinel `errFallbackUnimplemented` in this task, and the test only checks arming/retry. Keep the code compiling and old tests green.

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestFallback' -count=1`
`GOWORK=off go test ./internal/host -run 'TestDirect' -count=100` (the existing direct suite; expect the known flaky names if the baseline is flaky — compare against a stash baseline if needed)
Expected: PASS for the new tests; no new failures in `TestDirect`.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add internal/host/direct.go internal/host/punch_test.go internal/host/direct_test.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): arm punch fallback after seed failures"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 5: Spray side (Cone) executes the fallback

**Files:**
- Create: `p2p/internal/host/punchspray.go`
- Modify: `p2p/internal/host/direct.go` (`punch()` fallback branch, `markUp`)
- Test: `p2p/internal/host/punchspray_test.go`

**Interfaces:**
- `func randomPortTargets(ip netip.Addr, n int) []netip.AddrPort` — 1024–65535, unique, `n` clamped to 2048. Add `var randomPortTargetsFn = randomPortTargets` as the test seam.
- `func (dc *directConn) punchSpray(sock *net.UDPConn, peer netip.AddrPort, peerIP netip.Addr) (seedOutcome, error)`
- The `punch()` fallback branch: when `e.punch.mode == "spray"` and `fallbackReady`, call `punchSpray` with the v4 family socket and `peerV4[len(peerV4)-1]`; on success `markUp(sock, out.Answer, out.Token)`; on failure `dc.backoff()`.

Behavior:
- `punchSpray` builds `randomPortTargets(peerIP, e.punch.sprayPorts)` and runs `seedHandshakePlan` with `Peer = peer` (the announced endpoint, for retransmit/learn), `Targets = targets`, `SprayEvery = e.punch.sprayEvery`, `Grace = e.punch.seedGrace`; timeout = `e.punch.socketWindow`.
- The spray must use the same `sock` that produced the advertised p3.
- If the v4 family/socket is absent (no public candidate collected), skip the fallback and use the normal `backoff`.
- On success, `out.Answer` is the peer's q_i; the caller installs it.

- [ ] **Step 1: Write the failing test**

```go
func TestRandomPortTargets(t *testing.T) {
    got := randomPortTargets(netip.MustParseAddr("192.0.2.10"), 1000)
    if len(got) != 1000 { t.Fatalf("len = %d", len(got)) }
    seen := map[int]bool{}
    for _, ap := range got {
        if ap.Addr() != netip.MustParseAddr("192.0.2.10") { t.Fail() }
        if p := int(ap.Port()); p < 1024 || p > 65535 || seen[p] { t.Fatalf("bad port %d", p) }
        seen[p] = true
    }
}

func TestPunchSprayHitsOneTarget(t *testing.T) {
    // fake peer UDP socket; one of the sprayed ports belongs to it.
    // Run punchSpray with SprayPorts small and a controlled target set via a
    // test seam; assert seedOutcome.Answer == peer's address.
}
```
Add a `randomPortTargetsFn` seam or accept the target set in `punchSpray` for the test.

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestRandomPortTargets|TestPunchSpray' -count=1`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

Add `punchspray.go` with the target generator and `punchSpray`; wire the `punch()` branch. Use `math/rand` (not crypto) for port choice; the token stays crypto. Log only counts and the winner, never the full port list.

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestRandomPortTargets|TestPunchSpray' -count=1`
`GOWORK=off go test ./internal/host -run 'TestSeedPlan' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add internal/host/punchspray.go internal/host/punchspray_test.go internal/host/direct.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): spray random ports from the cone side"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 6: Sockets side (Random) executes the fallback

**Files:**
- Modify: `p2p/internal/host/punchspray.go` (or create `punchsockets.go`)
- Modify: `p2p/internal/host/direct.go` (`punch()` fallback branch)
- Test: `p2p/internal/host/punchsockets_test.go`

**Interfaces:**
- `func (dc *directConn) punchSockets(first *net.UDPConn, peer netip.AddrPort) (*net.UDPConn, seedOutcome, error)`
- Uses `first` plus `e.punch.sockets-1` new sockets bound by `bindAddrFor(e.stunAddr)`.
- Wait `min(e.punch.sprayEvery, 2s)` before starting the sends (a package var `socketStartDelay` so tests can shorten it): the spray side needs a head start.
- Each socket runs `seedHandshakePlan(sock, seedPlan{Peer: peer, Retransmit: seedRetransmit, Grace: e.punch.seedGrace}, e.punch.socketWindow)`.
- First success wins; close every other socket before returning; return the winner and outcome.
- If `first` is nil (no v4 candidate collection), skip the fallback.

- [ ] **Step 1: Write the failing test**

```go
func TestPunchSocketsStartDelay(t *testing.T) {
    // with socketStartDelay=10ms, the first send happens after ~10ms, not immediately.
}

func TestPunchSocketsWinner(t *testing.T) {
    // a fake peer that answers only one of N local sockets; assert the winner
    // is the answering socket and every other socket is closed.
}

func TestPunchSocketsWindow(t *testing.T) {
    // no peer; assert timeout, no winner, all sockets closed.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `GOWORK=off go test ./internal/host -run 'TestPunchSockets' -count=1`
Expected: FAIL — undefined.

- [ ] **Step 3: Implement**

Add `punchSockets`; wire the `punch()` branch for `mode == "sockets"`: use the v4 family socket as `first` and `peerV4[len(peerV4)-1]` as the peer p3; on success `markUp(win, out.Answer, out.Token)`; on failure `dc.backoff()`. Close losers with the existing ownership rules (the winner is handed to `markUp`, not closed by the function).

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestPunchSockets|TestSeedPlan' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add internal/host/punchsockets.go internal/host/punchsockets_test.go internal/host/punchspray.go internal/host/direct.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): open multiple sockets on the random side"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 7: Status, trace, and doctor

**Files:**
- Modify: `p2p/status.go` (`PeerDiagnostic`)
- Modify: `p2p/internal/host/direct.go` (fill fields from `directConn`)
- Modify: `p2p/doctor/doctor.go` (`punch mode` line; `caps` already prints `spray` via `capNames`)
- Test: `p2p/internal/host/punch_test.go`
- Test: `p2p/doctor/doctor_test.go`

**Interfaces:**
- `PeerDiagnostic` new fields: `PunchFallback string`, `FallbackRounds int`, `SprayPorts int`, `Sockets int`, `FallbackWinner string`, `FallbackError string` (in-process only).
- `punch` trace lines: `fallback spray ports=%d`, `fallback sockets=%d`, `fallback up via %s`.
- Doctor peer block: `punch mode: <spray|sockets|off>` and the existing `caps` line includes `spray`.

- [ ] **Step 1: Write the failing test**

```go
func TestPeerDiagnosticFallback(t *testing.T) {
    // directConn with punch mode spray and one fallback attempt;
    // assert diagnostic.PunchFallback == "spray", FallbackRounds == 1,
    // SprayPorts == settings, Sockets == settings.
}
```
And a doctor test asserting the `punch mode` line appears and `spray` is in the caps line.

- [ ] **Step 2: Run test to verify it fails**

Run:
`GOWORK=off go test ./internal/host -run 'TestPeerDiagnosticFallback' -count=1`
`GOWORK=off go test ./doctor -run 'TestPunchMode' -count=1`
Expected: FAIL — fields/lines missing.

- [ ] **Step 3: Implement**

Add fields and fill them in the status path; add the trace lines and doctor lines. Do not add UI or gRPC fields.

- [ ] **Step 4: Run tests to verify they pass**

Run:
`GOWORK=off go test ./internal/host -run 'TestPeerDiagnosticFallback' -count=1`
`GOWORK=off go test ./doctor -run 'TestPunchMode' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add status.go internal/host/direct.go internal/host/punch_test.go doctor/doctor.go doctor/doctor_test.go \
  docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "feat(p2p): report punch fallback diagnostics"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 8: netns e2e for Cone ↔ Random

**Files:**
- Modify: `p2p/tests/e2e/run.sh` (new scenario)
- Maybe: `p2p/tests/e2e/lib.sh` (NAT helper for `--random-fully`)
- Test: the scenario itself

**Interfaces:**
- Scenario name: `nat-cone-random`.
- Topology: two hosts, one behind a cone/port NAT (`MASQUERADE`), one behind `MASQUERADE --random-fully` (random symmetric).
- Host config: cone side `punch.mode: spray`; random side `punch.mode: sockets`.
- Assertion: the hub log contains `direct established` within the scenario budget; the control run with `punch.mode: off` stays `derp` (or no direct established).
- The scenario must run with the existing e2e harness (Docker/netns) and be added to the run list.

- [ ] **Step 1: Write the failing test**

Add the scenario; run:
`cd p2p/tests/e2e && ./run.sh nat-cone-random`
Expected initially: FAIL — no `direct established` / unknown scenario.

- [ ] **Step 2: Run to verify it fails**

Same command; capture the failure.

- [ ] **Step 3: Implement the scenario**

Add the NAT setup and the two configs; reuse the existing `scenario_derp_direct` helpers; do not duplicate the STUN/relay setup. If the existing harness cannot add `--random-fully`, add a small `lib.sh` helper. Ensure the control run (`mode: off`) is a separate assertion, not a second full topology if that doubles runtime.

- [ ] **Step 4: Run to verify it passes**

Run:
`cd p2p/tests/e2e && ./run.sh nat-cone-random`
Expected: PASS — `direct established` on the cone/random pair; control shows relay.

- [ ] **Step 5: Commit**

```bash
cd p2p
git add tests/e2e/run.sh tests/e2e/lib.sh docs/superpowers/plans/2026-11-28-p2p-cone-random-punch-plan.md
git commit -m "test(p2p): cover cone-random punch in netns"
```

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

### Task 9: Field verification (pi + Pixel 9 cellular)

**Files:** none in the p2p repo; this task records evidence in this plan.

**Steps:**

- [ ] Build the p2p binary from the branch and deploy it to the pi as the hub; build the phone component (the standalone `p2p` client or the wisper APK after the follow-up plan) with `punch.mode: sockets`.
- [ ] Hub config: `stun` as today; `punch.mode: spray`; the phone: `punch.mode: sockets`.
- [ ] Phone on cellular only (Wi-Fi off) or forced to rmnet1 for the test; run for 60s.
- [ ] Confirm in the hub log: a `fallback`/`spray` line, `direct established ... peerAddr=39.144.43.x:<q_i>`, and the doctor's `punch mode: spray`.
- [ ] Control: same run with `punch.mode: off`; confirm no direct established and the relay carries traffic.
- [ ] Record: date, commits, commands, logs (trimmed), result, limitations (carrier/region/time).

**Implementation record**

- Date/status:
- Repo/commit:
- Files changed:
- Tests/commands and results:
- Review findings and fixes:
- Deferred items/limitations:

---

## Follow-up (not this plan)

- wisper wiring: `P2PSettings.Punch` → `p2p.PunchConfig`; `p2pHostConfig`/`p2pHostSig`; API round-trip; hub YAML `p2p.punch.mode: spray`, phone `sockets`; UI deferred. This needs the p2p tag and a wisper `go.mod` bump.
- NAT auto-classification (Cone/Linear/Random) and the full 3×3 matrix; `LinearSymmeric` 50-prediction and `Both*` modes.
- IPv6: if the pi gets a global prefix, prefer v6; no code needed beyond the existing `p2p.ipv6`.
