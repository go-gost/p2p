# p2p runtime fault injection — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:subagent-driven-development
> or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

> **Commit policy:** this repo does not commit without explicit user approval. The
> `git commit` steps are the *intended* commits — run them only when the user has
> said to commit. Build/vet/test are the real gates for each task.

**Goal:** one opt-in config section makes the engine drop frames deliberately —
control, data, relay pongs, or a timed one-way silence — so a field failure can
be reproduced locally instead of guessed at.

**Why (the real payoff):** the direct-session 18s churn ([[p2p-direct-session-18s-churn]])
was only reproducible on a real phone on Wi-Fi, because the trigger was a ~12s
RF-batched *one-way silence*. With a `silence` injection that failure becomes a
deterministic in-process test with no phone involved — and it is the regression
check for the 15s timeout that fixed it.

**Non-goals:** no packet capture (the `recorder` is that tool), no injection of
*correct* frames (only omission), no per-peer targeting (process-wide, per the
decision), never on by default and never settable at runtime (config file only —
a shipped binary that can be told to drop traffic over a network API would be a
remote DoS surface).

**Decision record:** exposed in the config file only, process-wide, three
booleans plus one timed window; the fault set is `dropCtrl`, `dropData`,
`dropPong`, `silence`.

---

## File structure

| File | Responsibility |
|---|---|
| `config.go` (root) | `FaultsConfig` + `Config.Faults` — the contract (stdlib only, no lock-in to a transport). |
| `internal/host/faults.go` (new) | the live fault state: built from the config once, read by the injection points without a lock on the hot path. |
| `internal/host/engine.go`, `internal/derpclient/*.go` | the injection points (outbound control/data, inbound pump, pong handling). |
| `internal/host/direct.go` | the direct path's own send/drop points (data, silence). |
| `README.md`, `CLAUDE.md`, `docs/embedding.md` | the section, with the "never enable this in production" warning. |

---

## Task 1: the config surface

**Files:**
- Modify: `config.go`
- Test: `config_test.go` (root) — or cover via Task 2's apply test; the root already has `deps_test.go` guarding imports.

- [ ] **Step 1: add the type and the field**

```go
// FaultsConfig deliberately breaks the transport to reproduce a field failure
// locally: each knob makes the engine drop frames it would otherwise send or
// deliver. Every knob is off in the zero value, and a process that enables one
// says so loudly at startup.
//
// This is a debugging tool, not a feature. An injected drop is indistinguishable
// from a real one at every layer above, which is the point — and why it must
// never be enabled in a deployment that matters. It is config-file only: there
// is no RPC, no env var and no flag, so a running host cannot be told to break
// itself over the network.
type FaultsConfig struct {
	// DropCtrl drops every control-plane frame on the relay path: the candidate
	// exchange, ctrlSecure, ctrlCaps. A punch round then fails to settle (or
	// never starts), which is what a peer that cannot negotiate looks like.
	DropCtrl bool `yaml:"dropCtrl" json:"dropCtrl"`
	// DropData drops every data frame — tunnel payload and the smux keepalive
	// alike — on both the relay and the direct path.
	DropData bool `yaml:"dropData" json:"dropData"`
	// DropPong swallows the relay's pong replies, so a live relay looks silent
	// and the relay-silence watchdog is what a reader sees.
	DropPong bool `yaml:"dropPong" json:"dropPong"`
	// Silence stops sending *anything* to the peer for SilenceFor, every
	// SilenceEvery, while SilenceEvery > 0. This is the measured field failure:
	// the session's peer-side frames stop arriving without the path dying, and
	// the direct session lives or dies by its keepalive timeout (a timeout
	// shorter than SilenceFor tears it down; the shipped 15s survives).
	SilenceFor   time.Duration `yaml:"silenceFor" json:"silenceFor"`
	SilenceEvery time.Duration `yaml:"silenceEvery" json:"silenceEvery"`
}
```

and on `Config`:

```go
	// Faults injects deliberate transport failures (debug only — see
	// FaultsConfig). Nil or zero means nothing is injected.
	Faults *FaultsConfig `yaml:"faults" json:"faults"`
```

- [ ] **Step 2: build + fmt**

Run: `go build ./... && gofmt -l .` — the root must stay stdlib-only
(`TestContractsAreStdlibOnly`); `time` is stdlib, so it passes.

- [ ] **Step 3: commit (gated)**

```bash
git add config.go && git commit -m "contracts: a debug-only fault injection section"
```

---

## Task 2: the live state

**Files:**
- Create: `internal/host/faults.go`
- Test: `internal/host/faults_test.go`

- [ ] **Step 1: write the failing test**

```go
func TestFaultsOffByDefault(t *testing.T) {
	f := newFaults(nil)
	if f.ctrl() || f.data() || f.pong() || f.silenced(time.Now()) {
		t.Fatal("a nil config must inject nothing")
	}
}

func TestFaultsSilenceWindow(t *testing.T) {
	f := newFaults(&p2p.FaultsConfig{SilenceFor: time.Second, SilenceEvery: 10 * time.Second})
	start := time.Unix(0, 0)
	if !f.silenced(start) {
		t.Fatal("the window must start muted")
	}
	if !f.silenced(start.Add(999 * time.Millisecond)) {
		t.Fatal("inside the window must stay muted")
	}
	if f.silenced(start.Add(2 * time.Second)) {
		t.Fatal("outside the window must send")
	}
	if !f.silenced(start.Add(10 * time.Second)) {
		t.Fatal("the next window must mute again")
	}
	// A Forget-For without an Every is a no-op, not a permanent mute.
	if g := newFaults(&p2p.FaultsConfig{SilenceFor: time.Second}); g.silenced(start) {
		t.Fatal("silenceFor without silenceEvery must inject nothing")
	}
}
```

- [ ] **Step 2: run it (fails: undefined: newFaults)**

Run: `cd p2p && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 -run TestFaults ./internal/host/`

- [ ] **Step 3: implement**

```go
// faults is the process-wide injection state, built once from the config. The
// hot-path readers (ctrl/data/pong) are plain booleans behind atomics: a
// disabled injection must cost nothing.
type faults struct {
	dropCtrl, dropData, dropPong atomic.Bool
	silenceFor, silenceEvery     time.Duration
	since                        time.Time // the window's origin
}

// newFaults builds the state and logs a warning for every enabled knob. cfg may
// be nil (the common case: everything off).
func newFaults(cfg *p2p.FaultsConfig) *faults { ... }

func (f *faults) ctrl() bool { return f != nil && f.dropCtrl.Load() }
func (f *faults) data() bool { return f != nil && f.dropData.Load() }
func (f *faults) pong() bool { return f != nil && f.dropPong.Load() }

// silenced reports whether the process is inside a silence window now. Both
// durations must be set: a for-without-every would be a permanent mute.
func (f *faults) silenced(now time.Time) bool { ... }
```

Call it from `host.New` next to the other `apply*` helpers, and store it on the
host/engine so the injection points can read it. Log once, at warn, listing what
is on — a fault-injected host must never be mistaken for a broken one.

- [ ] **Step 4: run the tests** — green.

- [ ] **Step 5: commit (gated)**

```bash
git add internal/host/faults.go internal/host/faults_test.go internal/host/host.go
git commit -m "host: hold the fault injection state, off unless configured"
```

---

## Task 3: the injection points

**Files:**
- Modify: `internal/host/engine.go` (relay send/pump), `internal/derpclient/*.go` (pong), `internal/host/direct.go` (direct send)
- Test: `internal/host/faults_test.go` (extend) or `internal/host/engine_test.go`

The points, one line each, at the narrowest place that covers both directions:

| Knob | Where | Effect |
|---|---|---|
| `dropCtrl` | the relay control send (`sendCandidates`/`sendCaps`/ctrlSecure) **and** the pump's control delivery | the punch never settles; the peer stays on relay |
| `dropData` | the relay data send, the pump's data delivery, and the direct smux write | the session starves (keepalive NOPs included) |
| `dropPong` | `derpclient`'s pong handling (both the reply and the bookkeeping that feeds the watchdog) | the relay reads as silent |
| `silence` | the same send paths as `dropData`, gated by `silenced(now)` and covering control too | a timed one-way silence |

- [ ] **Step 1: write the failing tests** — one per knob, each asserting the
  *symptom* rather than the call:

```go
// dropData: an established direct session dies after the keepalive timeout,
// i.e. the 18s field failure, reproduced in-process.
func TestDropDataStarvesADirectSession(t *testing.T) { ... }

// silence: a session survives a silence shorter than its timeout and dies
// beyond it — the exact regression the 15s default fixes.
func TestSilenceShorterThanTimeoutIsSurvived(t *testing.T) { ... }
```

Use the existing in-process relay double and the package's shortened timings
(`TestMain`); a silence of `3 * directSmuxKeepAliveTimeout` must kill a session,
one of `directSmuxKeepAliveTimeout / 2` must not.

- [ ] **Step 2: run them (they fail without the injection)**

- [ ] **Step 3: wire the injection points** — a guard at each site that returns
  early; no allocation, no log on the hot path (the startup warning is the log).

- [ ] **Step 4: run the package tests**

Run: `cd p2p && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./internal/host/ ./internal/derpclient/`
Expected: green (`TestSeedHandshake` is a known sandbox flake — rerun if only it fails).

- [ ] **Step 5: commit (gated)**

```bash
git add internal/host internal/derpclient
git commit -m "host: inject control, data, pong and silence faults for reproduction"
```

---

## Task 4: docs

**Files:**
- Modify: `README.md`, `README.zh-CN.md`, `CLAUDE.md`, `docs/embedding.md`

- [ ] **Step 1: write the section.** In README (both languages) under a
  "Fault injection (debug only)" heading: the four knobs, a config example, the
  startup warning, and the sentence that matters — *an injected failure is
  indistinguishable from a real one, so never enable this where it can confuse
  someone*. CLAUDE.md: one paragraph + the package-layout note that the state
  lives in `internal/host/faults.go`. embedding.md: `Config.Faults` in the
  config reference, with the same warning.

- [ ] **Step 2: verify**

Run: `go build ./... && go vet ./... && gofmt -l . && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./...` (per package if the wildcard is slow).

- [ ] **Step 3: commit (gated)**

```bash
git add README.md README.zh-CN.md CLAUDE.md docs/embedding.md
git commit -m "docs: the debug-only fault injection section"
```
