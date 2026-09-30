# p2p per-peer diagnostics — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Commit policy:** this repo does not commit without explicit user approval. The
> `git commit` steps are the *intended* commits — run them only when the user has
> said to commit. Build/vet/test are the real gates for each task.

**Goal:** Expose one live diagnostic snapshot per connected peer — path, reason,
punch state, last error, dialled endpoint, candidate count, caps, session and
silence ages, counters — in `Status`, over gRPC, and in the wisper peers page.

**Architecture:** The engine already holds nearly all of it in `directConn`
(`state`, `failed`, `peerAddr`, `lastPeer`, `peerCaps`, `attempts/ups/drops`) and
`peerConn`. Three fields are added (a last punch error, the direct session's
start time, a per-peer last-frame timestamp), a `peerDiagnostics()` builder
replaces `peerPunches()`, and `Status.PeerPunches` is superseded by
`Status.PeerDiagnostics`. A repeated `PeerDiagnostic` message carries it over
gRPC, and wisper passes it through to a per-row expand on the peers page.

**Tech Stack:** Go 1.26 (workspace), `net/netip`, `sync/atomic`, protobuf
(`protoc` pinned in the plugin proto header).

Design spec: [docs/2026-09-30-p2p-peer-diagnostics-design.md](docs/2026-09-30-p2p-peer-diagnostics-design.md).

---

## File structure

| File | Responsibility |
|---|---|
| `internal/host/direct.go` | `directConn.lastErr`/`sessAt`; `noteErr` at the punch failure points; the snapshot's per-peer source. |
| `internal/host/engine.go` | `peerConn.lastFrameAt`; `peerDiagnostics()` builder; drop `peerPunches()`. |
| `internal/host/server.go` | `status()` fills `PeerDiagnostics` instead of `PeerPunches`. |
| `status.go` (root) | `PeerDiagnostic` type; `Status.PeerDiagnostics` (supersedes `PeerPunches`). |
| `grpc/rpc.go` | map `PeerDiagnostics` onto the proto's repeated message. |
| `../plugin/p2p/proto/p2p.proto` | `PeerDiagnostic` message + `repeated` field on `StatusReply`. |
| `../wisper/api/*.go`, `web-src/src/**` | pass the snapshot through; the peers-page expand. |

---

## Task 1: the three new engine fields

**Files:**
- Modify: `internal/host/direct.go`, `internal/host/engine.go`
- Test: `internal/host/direct_test.go`, `internal/host/engine_test.go`

- [x] **Step 1: Write the failing test**

A punch failure must record its reason. In `internal/host/direct_test.go`:

```go
func TestDirectConnRecordsLastError(t *testing.T) {
	dc := &directConn{}
	dc.noteErr("seed timeout")
	if got := dc.lastErrOf(); got != "seed timeout" {
		t.Fatalf("lastErr = %q, want %q", got, "seed timeout")
	}
	// A successful session clears it.
	dc.mu.Lock()
	dc.lastErr = ""
	dc.mu.Unlock()
	if got := dc.lastErrOf(); got != "" {
		t.Fatalf("lastErr = %q, want empty", got)
	}
}
```

(`sessAt` has no cheap unit test — `markUp` needs a real `*smux.Session`. It is
covered instead by Task 2's snapshot test, which asserts `SessionAge > 0` when
the path is `direct`.)

- [x] **Step 2: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run 'TestDirectConnRecordsLastError' -v`
Expected: FAIL — `dc.noteErr undefined`.

- [x] **Step 3: Add the fields + accessors + `noteErr`**

In `internal/host/direct.go`, add to `directConn` (next to `peerCaps`):

```go
	peerCaps uint8          // capability bits the peer advertised via ctrlCaps
	lastErr  string         // the last punch failure's reason, cleared when one succeeds
	sessAt   time.Time      // when the live direct session came up (zero when none)
```

Add the accessors and the recorder:

```go
// noteErr records why a punch round failed. The latest reason wins: it is what a
// status reader (and a support case) needs, and it is cleared by markUp.
func (dc *directConn) noteErr(reason string) {
	dc.mu.Lock()
	dc.lastErr = reason
	dc.mu.Unlock()
}

// lastErrOf reads the last punch failure's reason.
func (dc *directConn) lastErrOf() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.lastErr
}

// sessAtOf reads when the live direct session came up.
func (dc *directConn) sessAtOf() time.Time {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.sessAt
}
```

In `markUp`, stamp the session and clear the error (inside the existing lock):

```go
	dc.sess = sess
	dc.socket = socket
	dc.peerAddr = peerAddr
	dc.state = directUp
	dc.failed = false
	dc.lastErr = ""
	dc.sessAt = time.Now()
	dc.mu.Unlock()
```

- [x] **Step 4: Record the reason at each punch failure point**

In `punch`/`retry`, call `dc.noteErr(...)` where the round gives up for that
peer. The call sites (line numbers from the current file — adapt to the real
ones):

| Where | Reason to record |
|---|---|
| `no peer candidates` → `backoff` (~666) | `"no peer candidates"` |
| `no shared family` → `backoff` (~701) | `"no shared family"` |
| dial failed → `continue` (~819) | `fmt.Sprintf("dial failed: %v", err)` |
| `seed failed` → `continue` (~823) | `fmt.Sprintf("seed failed: %v", err)` |
| smux failed → `continue` (~849) | `fmt.Sprintf("smux failed: %v", err)` |
| encryption not settled → `backoff` | `"encryption not settled"` |

Example for the seed site:

```go
		if err := seedHandshake(kcpConn, seedTimeout); err != nil {
			kcpConn.Close() // ownConn=true closes f.sock with it
			dc.noteErr(fmt.Sprintf("seed failed: %v", err))
			e.log.Debug("direct punch: seed failed", "peer", pname, "family", f.name, "addr", u.String(), "error", err)
			continue
		}
```

- [x] **Step 5: Add `peerConn.lastFrameAt`**

In `internal/host/engine.go`, add to `peerConn`:

```go
	lastFrameAt atomic.Int64 // UnixNano of the last frame seen from this peer (relay)
```

In `pump`, when a frame from `src` is routed (right after `pc := e.peerConn(src)`):

```go
		pc := e.peerConn(src)
		pc.lastFrameAt.Store(time.Now().UnixNano())
```

- [x] **Step 6: Run the tests**

Run: `cd p2p && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./internal/host/`
Expected: green (`TestSeedHandshake` is a known sandbox flake — rerun if only it fails).

- [x] **Step 7: Commit (gated)**

```bash
cd p2p && git add internal/host/direct.go internal/host/engine.go internal/host/direct_test.go
git commit -m "host: record the punch failure reason, session start and last frame"
```

---

## Task 2: the snapshot and `Status`

**Files:**
- Modify: `status.go`, `internal/host/engine.go`, `internal/host/server.go`
- Test: `internal/host/engine_test.go`

- [x] **Step 1: Write the failing test**

```go
func TestPeerDiagnosticsSnapshot(t *testing.T) {
	eA, eB, rs := newEncryptedPair(t)
	defer rs.Close()

	conn, err := eA.OpenStream(eB.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	go conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	st := newServer(eA).status()
	d, ok := st.PeerDiagnostics[eB.PublicKey()]
	if !ok {
		t.Fatal("no diagnostic for the peer")
	}
	if d.Path != "direct" && d.Path != "derp" {
		t.Fatalf("path = %q", d.Path)
	}
	if d.Attempts == 0 {
		t.Fatal("attempts not reported")
	}
	if d.LastRecvAge <= 0 {
		t.Fatal("last-recv age not reported for a peer that just sent")
	}
	// A live direct session carries its age. The sandbox may keep this pair on
	// the relay (the punch's UDP send is denied here), so assert only when the
	// path really is direct.
	if d.Path == "direct" && d.SessionAge <= 0 {
		t.Fatal("a direct session must carry its age")
	}
}
```

- [x] **Step 2: Run the test to verify it fails**

Run: `cd p2p && go test ./internal/host/ -run TestPeerDiagnosticsSnapshot -v`
Expected: FAIL — `st.PeerDiagnostics undefined`.

- [x] **Step 3: Add the type and supersede `PeerPunches`**

In `status.go`, replace the `PeerPunch` type + the `PeerPunches` field with:

```go
// PeerDiagnostic is one connected peer's live state: where its traffic goes, why,
// and enough detail (the last error, the dialled endpoint, the ages) to diagnose
// it without raising the log level. It supersedes the old punch counters, which
// it carries.
type PeerDiagnostic struct {
	// Path is the current transport word: "direct", "punching", "failed",
	// "derp", "disabled", "no-candidates" or "stun-unreachable".
	Path string
	// Reason is the host-wide cause when it outranks this peer's own round
	// ("no-candidates", "stun-unreachable", "disabled"), else empty.
	Reason string
	// State is the punch state machine: "none", "attempting", "up" or "backoff".
	State string
	// Failed reports a punch round that has failed (sticky).
	Failed bool
	// LastError is the last punch failure's reason (empty after a success).
	LastError string
	// PeerAddr is the endpoint dialled for the direct path (empty until a round
	// dials). Candidates is how many the peer announced.
	PeerAddr   string
	Candidates int
	// Caps is the peer's advertised capabilities ("ipv6", "tightKeepalive").
	Caps []string
	// SessionAge is how long the live direct session has been up (0 when none);
	// LastRecvAge is how long since the last frame from the peer.
	SessionAge  time.Duration
	LastRecvAge time.Duration
	// Attempts/Ups/Drops are the peer's punch history (what PeerPunch held).
	Attempts int64
	Ups      int64
	Drops    int64
}
```

and on `Status`:

```go
	// PeerDiagnostics is each connected peer's live state, keyed by base64
	// public key. In-process only: the proto carries the aggregate gauges.
	PeerDiagnostics map[string]PeerDiagnostic
```

Delete the `PeerPunch` type and the `PeerPunches` field.

- [x] **Step 4: Build the snapshot**

In `internal/host/engine.go`, replace `peerPunches()` with:

```go
// peerDiagnostics snapshots each connected peer. The host-wide reason is read
// once and applies to every peer it outranks; the per-peer fields come from the
// adapter and the punch state machine, read without probing a session.
func (e *engine) peerDiagnostics() map[string]p2p.PeerDiagnostic {
	e.mu.Lock()
	peers := make([]*peerConn, 0, len(e.peers))
	for _, pc := range e.peers {
		peers = append(peers, pc)
	}
	directs := make([]*directConn, 0, len(e.directs))
	for _, dc := range e.directs {
		directs = append(directs, dc)
	}
	e.mu.Unlock()

	reason := e.directReason()
	transports := e.peerTransports()

	now := time.Now()
	out := make(map[string]p2p.PeerDiagnostic, len(peers)+len(directs))
	for _, pc := range peers {
		out[keyName(pc.peer)] = p2p.PeerDiagnostic{Reason: reason, LastRecvAge: ageOf(now, pc.lastFrameAt.Load())}
	}
	for _, dc := range directs {
		name := keyName(dc.peer)
		d := out[name] // keep a relay connector's lastFrame age if there is one
		d.Path = transports[name]
		if reason != "" {
			d.Reason = reason
		}
		d.State = dc.stateName()
		d.Failed = dc.hasFailed()
		d.LastError = dc.lastErrOf()
		d.PeerAddr = dc.peerAddrString()
		d.Candidates = dc.candidateCount()
		d.Caps = dc.capNames()
		if !dc.sessAtOf().IsZero() {
			d.SessionAge = now.Sub(dc.sessAtOf())
		}
		d.Attempts, d.Ups, d.Drops = dc.punchCounters()
		out[name] = d
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ageOf is the time since a UnixNano stamp, or 0 when unset.
func ageOf(now time.Time, nano int64) time.Duration {
	if nano == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, nano))
}
```

Add these small accessors in `internal/host/direct.go` (the existing
`punchCounts` returns a `p2p.PeerPunch`, which no longer exists — replace it):

```go
func (dc *directConn) stateName() string {
	switch dc.stateOf() {
	case directAttempting:
		return "attempting"
	case directUp:
		return "up"
	case directBackoff:
		return "backoff"
	default:
		return "none"
	}
}

// peerAddrString is the dialled endpoint, empty until a round dials.
func (dc *directConn) peerAddrString() string {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.peerAddr.String()
}

// candidateCount is how many candidates the peer last announced.
func (dc *directConn) candidateCount() int {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return len(dc.lastPeer)
}

// capNames names the capability bits the peer advertised.
func (dc *directConn) capNames() []string {
	dc.mu.Lock()
	bits := dc.peerCaps
	dc.mu.Unlock()
	var out []string
	if bits&capsIPv6 != 0 {
		out = append(out, "ipv6")
	}
	if bits&capsTightKeepalive != 0 {
		out = append(out, "tightKeepalive")
	}
	return out
}

// punchCounters is the per-peer punch history without the p2p.PeerPunch type
// (which Status no longer has). Replaces punchCounts — it has one caller,
// peerPunches, also removed here.
func (dc *directConn) punchCounters() (attempts, ups, drops int64) {
	return dc.attempts.Load(), dc.ups.Load(), dc.drops.Load()
}
```

(`peerAddr.String()` on a zero `netip.AddrPort` is `"invalid AddrPort"` — guard
it: return `""` when `!dc.peerAddr.IsValid()`.)

- [x] **Step 5: Wire it into `status()`**

In `internal/host/server.go`:

```go
		st.PeerTransports = s.engine.peerTransports()
		st.PeerDiagnostics = s.engine.peerDiagnostics()
		st.PeerEncryption = s.engine.peerEncryptions()
```

- [x] **Step 6: Run the tests**

Run: `cd p2p && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./internal/host/`
Expected: green. Fix every reader of the removed `PeerPunches` (grep `PeerPunches`, `peerPunches`, `punchCounts`).

- [x] **Step 7: Commit (gated)**

```bash
cd p2p && git add status.go internal/host/engine.go internal/host/direct.go internal/host/server.go internal/host/engine_test.go
git commit -m "host: report a per-peer diagnostic snapshot in Status"
```

---

## Task 3: over gRPC

**Files:**
- Modify: `../plugin/p2p/proto/p2p.proto`, `grpc/rpc.go`
- Test: `grpc/rpc_test.go`

- [x] **Step 1: Extend the proto**

In `../plugin/p2p/proto/p2p.proto`, add a message and a field:

```proto
// PeerDiagnostic is one connected peer's live state, as Status reports it.
message PeerDiagnostic {
	string path        = 1;
	string reason      = 2;
	string state       = 3;
	bool   failed      = 4;
	string last_error  = 5;
	string peer_addr   = 6;
	int32  candidates  = 7;
	repeated string caps = 8;
	int64  session_age_ms  = 9;
	int64  last_recv_age_ms = 10;
	int64  attempts = 11;
	int64  ups      = 12;
	int64  drops    = 13;
}
```

and on `StatusReply`:

```proto
	repeated PeerDiagnostic peer_diagnostics = 10;
```

Regenerate with the pinned toolchain (from the `plugin` dir):

```bash
protoc --proto_path=. --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative p2p/proto/p2p.proto
```

- [x] **Step 2: Write the failing test**

The mapping is a pure function, so it is tested without a live endpoint (the
grpc tests here have no relay harness, so a `Status` round trip has no peers).
In `grpc/rpc_test.go`:

```go
func TestPeerDiagnosticsToProto(t *testing.T) {
	in := map[string]p2p.PeerDiagnostic{
		"peerA": {
			Path: "failed", Reason: "stun-unreachable", State: "backoff",
			Failed: true, LastError: "seed failed: timeout",
			PeerAddr: "192.0.2.10:34567", Candidates: 2,
			Caps: []string{"ipv6"}, SessionAge: 3 * time.Second,
			LastRecvAge: 1500 * time.Millisecond, Attempts: 7, Ups: 1, Drops: 2,
		},
	}
	out := peerDiagnosticsToProto(in)
	if len(out) != 1 {
		t.Fatalf("got %d diagnostics", len(out))
	}
	got := out[0]
	if got.Path != "failed" || got.Reason != "stun-unreachable" || !got.Failed ||
		got.LastError != "seed failed: timeout" || got.PeerAddr != "192.0.2.10:34567" ||
		got.Candidates != 2 || got.Attempts != 7 || got.Ups != 1 || got.Drops != 2 {
		t.Fatalf("mapping wrong: %+v", got)
	}
	if got.SessionAgeMs != 3000 || got.LastRecvAgeMs != 1500 {
		t.Fatalf("ages wrong: %d / %d", got.SessionAgeMs, got.LastRecvAgeMs)
	}
	if len(got.Caps) != 1 || got.Caps[0] != "ipv6" {
		t.Fatalf("caps wrong: %v", got.Caps)
	}
}
```

- [x] **Step 3: Map it**

In `grpc/rpc.go`, add the pure mapper and call it from `Status`:

```go
// peerDiagnosticsToProto maps the status snapshot onto the wire form, ordered by
// peer key for a stable reply. Pure, so the mapping is tested without a live
// endpoint.
func peerDiagnosticsToProto(in map[string]p2p.PeerDiagnostic) []*pb.PeerDiagnostic {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]*pb.PeerDiagnostic, 0, len(in))
	for _, k := range keys {
		d := in[k]
		out = append(out, &pb.PeerDiagnostic{
			Path:          d.Path,
			Reason:        d.Reason,
			State:         d.State,
			Failed:        d.Failed,
			LastError:     d.LastError,
			PeerAddr:      d.PeerAddr,
			Candidates:    int32(d.Candidates),
			Caps:          d.Caps,
			SessionAgeMs:  d.SessionAge.Milliseconds(),
			LastRecvAgeMs: d.LastRecvAge.Milliseconds(),
			Attempts:      d.Attempts,
			Ups:           d.Ups,
			Drops:         d.Drops,
		})
	}
	return out
}
```

and in the `Status` handler:

```go
	reply.PeerDiagnostics = peerDiagnosticsToProto(st.PeerDiagnostics)
```

The proto message carries no peer key — a client already knows the keys it asked
by; add `string peer = 14` and fill it only if a keyless list proves awkward.

- [x] **Step 4: Verify**

Run: `cd ../plugin && go build ./... && cd ../p2p && go build ./... && go vet ./... && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./grpc/ ./internal/host/`
Expected: green. Note: the `p2p` standalone build (`GOWORK=off`) will be red
until the `plugin` tag is pushed and `p2p`'s pin bumped (the release step).

- [x] **Step 5: Commit (gated)**

```bash
cd ../plugin && git add p2p/proto/p2p.proto p2p/proto/*.go && git commit -m "plugin: add per-peer diagnostics to StatusReply"
cd ../p2p && git add grpc/rpc.go grpc/rpc_test.go && git commit -m "grpc: carry per-peer diagnostics"
```

---

## Task 4: wisper API and UI

**Files:**
- Modify: `../wisper/runner/task/diff.go`, `../wisper/runner/task/stats.go`, `../wisper/api/p2p_handler.go`, `../wisper/api/tunnel_handler.go`, `../wisper/web-src/src/**`
- Test: `../wisper/runner/task/diff_test.go`, `../wisper/api/api_test.go`, `../wisper/web-e2e/tests/*.spec.ts`

> **Found while executing Task 2:** removing `p2p.PeerPunch` breaks **more of wisper
> than the API** — `runner/task` reads the punch counters directly
> (`diffPunchDrops`/`diffPunchFailures` take `map[string]p2p.PeerPunch`; `stats.go`
> reads `st.PeerPunches`). The workspace (go.work) build is red from Task 2 until
> this task lands. The p2p module itself stays green (verify per module).

- [x] **Step 0: migrate the punch-counter readers in `runner/task`**

`diffPunchDrops`/`diffPunchFailures` change their parameter to
`map[string]p2p.PeerDiagnostic` and read `d.Drops` / `d.Attempts - d.Ups` (the
same fields, renamed); `stats.go` reads `st.PeerDiagnostics` for `t.punches` (and
`t.peers` keeps `PeerTransports`). Update `diff_test.go` to build
`PeerDiagnostic` instead of `PeerPunch`. Run `cd ../wisper &&
CGO_ENABLED=1 go test -race ./runner/... ./event/`.

- [x] **Step 1: Pass it through the API**

`../wisper/api/p2p_handler.go`: expose `PeerDiagnostics` (add a
`peer_diagnostics` array to the `/api/p2p` response, or fold the fields into the
existing `PeerStats` in `tunnel_handler.go`, which already carries `transport`).
Prefer folding into `peerStatsJSON` — the peers page already reads it:

```go
type peerStatsJSON struct {
	Key             string `json:"key"`
	Alias           string `json:"alias,omitempty"`
	Transport       string `json:"transport,omitempty"`
	Reason          string `json:"reason,omitempty"`
	State           string `json:"state,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	PeerAddr        string `json:"peer_addr,omitempty"`
	Candidates      int    `json:"candidates"`
	Caps            []string `json:"caps,omitempty"`
	SessionAgeMs    int64  `json:"session_age_ms,omitempty"`
	LastRecvAgeMs   int64  `json:"last_recv_age_ms,omitempty"`
	// ...the existing counters
}
```

Fill it from `tunnel.P2PHostStatus().PeerDiagnostics[p.Key]`.

- [x] **Step 2: The peers-page expand**

In `../wisper/web-src/src/pages/tunnel-peers-page.ts`, add a per-row expand
(mirroring the row's existing structure): the path + reason, the punch state and
last error, the dialled endpoint, the candidate count and caps, the session and
silence ages. Add i18n keys to **both** `en.ts` and `zh.ts` for each label; the
values (`direct`, `failed`, …) come from the engine and are shown as-is.

- [x] **Step 3: Verify**

`../wisper`: `go build ./...`, `GOWORK=off go build ./...`, `go vet ./...`,
`gofmt -l .`, `go test ./api/`, then `make web` and `cd web-src && npx tsc
--noEmit`, and `make ui-test` (add a spec asserting the expand shows the path).

- [x] **Step 4: Commit (gated)**

```bash
cd ../wisper && git add api/ web-src/src web/ && git commit -m "web: show a peer's diagnostics on the peers page"
```

---

## Task 5: docs and release

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `docs/2026-09-30-p2p-peer-diagnostics-design.md`

- [x] **Step 1: Update the docs**

- `README.md` / `CLAUDE.md`: the `Status` bullet — `PeerDiagnostics` (superseding
  `PeerPunches`), what each field answers, in-process vs the gRPC repeated
  message.
- The design doc: turn "Status: proposed" into "implemented" once it is.

- [x] **Step 2: Full verification**

Run: `cd p2p && go build ./... && go vet ./... && gofmt -l . && TMPDIR=/config/tmp CGO_ENABLED=1 go test -race -count=1 ./...` (per package if the wildcard is slow).
Expected: green (workspace). The standalone `GOWORK=off` build needs the plugin
release below.

- [ ] **Step 2b: e2e**

In the container harness (`tests/e2e/run.sh` + the `helper`), extend a scenario's
`Status` assertion: after a tunnel is up, the queried status carries a
`PeerDiagnostics` entry whose `path` is `direct` or `derp` and whose `attempts`
moved. Run one scenario (e.g. `derp-relay`) in the privileged container and
confirm.

- [ ] **Step 3: Release ordering (gated)**

1. Push a `plugin` tag with the proto addition, then bump `p2p`'s `plugin`
   requirement + `go.sum` (`go mod edit -require=…` + `GOWORK=off go mod
   download …` — do **not** use `go get`/`go mod tidy` in this environment).
2. Verify `GOWORK=off go build ./...` in `p2p`, then tag `p2p`.
3. Bump `wisper` to the new `p2p` and release (the desktop/APK pipeline).

---

## Open implementation notes

- **`peerTransports()` and `peerDiagnostics()` both build the per-peer maps**;
  they are called once each per status tick. If that shows up, fold them into
  one builder returning both.
- **The relay connector's `lastFrameAt`**: a peer with only a relay adapter (no
  `directConn`) still gets `Reason`/`LastRecvAge`. A peer with both takes the
  direct row's fields plus the relay's recv age (the `out[name]` seed above).
- **`peerAddr` zero value**: guard `netip.AddrPort.IsValid()` before `.String()`.
