# p2p per-peer diagnostics — design

Status: **implemented** (2026-09-30). Turns "grep the debug log of a running peer"
into one structured snapshot per peer, in `Status` and over gRPC.

## Context (why)

Diagnosing a p2p problem today means raising the log level and reading a dense
debug stream. The state that answers the questions is already in the engine but
mostly has no outlet:

- `Status.PeerTransports` gives ONE WORD per peer (`direct` / `punching` /
  `failed` / `derp` / `disabled` / `no-candidates` / `stun-unreachable`) — the
  *path*, never the *reason detail*.
- `Status.PeerPunches` gives `attempts`/`ups`/`drops` — the *how often*.
- Everything else — which endpoint was dialled, what candidates the peer
  announced, why the last round failed, how long the session or the silence has
  lasted — exists in `directConn`/`peerConn` (or in the log) and reaches nobody.

A support case ("the peer is on the relay and I don't know why", "the session
keeps dying", "after a network switch nothing works") therefore needs a
human-readable snapshot, not a log level.

## Design

### The snapshot

One `PeerDiagnostic` per connected peer, in `p2p.Status`. It supersedes
`PeerPunches` (it carries the same counters) so there is one per-peer map, not
three.

| Field | Source | Notes |
|---|---|---|
| `Path` | `peerTransports()` | the current word, unchanged |
| `Reason` | `directReason()` | the host-wide cause when it outranks the peer's own (`no-candidates` / `stun-unreachable` / `disabled`), else `""` |
| `State` | `directConn.stateOf()` | `none` / `attempting` / `up` / `backoff` — the state machine, which the word folds away |
| `Failed` | `directConn.hasFailed()` | sticky, as today |
| `LastError` | **new** `directConn.lastErr` | e.g. `seed timeout`, `no shared family`, `dial failed` — set at each failure point instead of only logged |
| `PeerAddr` | `directConn.peerAddr` | the endpoint actually dialled (empty until a round dials) |
| `Candidates` | `directConn.lastPeer` | the peer's announced candidate count (addresses are the peer's own, so a count is enough by default; see Open items) |
| `Caps` | `directConn.peerCaps` | `ipv6`, `tightKeepalive` |
| `SessionAge` | **new** `directConn.sessAt` | how long the live direct session has been up (0 when none) |
| `LastRecvAge` | **new** per-peer `lastFrameAt` | time since the last frame from the peer, relay or direct — the signal a silent peer is otherwise invisible by |
| `Attempts` / `Ups` / `Drops` | `directConn` atomics | as `PeerPunches` today |

Over gRPC each entry also names the peer — `peer`, field 14, the base64 key — so
the repeated list is attributable (a keyless list would leave two relay-only
peers byte-identical).

New engine state is small: `lastErr` (a string set at the punch failure points),
`sessAt` (one assignment in `markUp`), `lastFrameAt` (one atomic store in the
relay pump and the direct accept loop).

### Surfaces

- **`p2p.Status.PeerDiagnostics map[string]PeerDiagnostic`** (base64 key →
  snapshot), in-process, replacing `PeerPunches`. wisper's `/api/p2p` and
  `/api/entrypoints/{id}` pass it through; the peers page shows it per row
  (a details affordance — path/reason/last error/endpoint/ages), so the UI
  states *why*, not just a badge.
- **gRPC**: `StatusReply` gains a repeated `PeerDiagnostic peer_diagnostics = 10`
  (path, reason, state, last_error, peer_addr, candidates, caps, ages, counters),
  so `grpcurl` and any plugin client see per-peer detail. Aggregate gauges are
  unchanged. This is a `plugin/p2p/proto` addition → a plugin release + a `p2p`
  bump.
- **Diagnostics stay cheap to read**: like `peerTransports`, the snapshot reads
  each conn's fields without taking `pc.mu`/`dc.mu` where the value is an atomic
  or a plain field, and never probes a session (`live()` only, never `session()`).

### Non-goals

- No new persistence: the snapshot is live state, not history (the event log
  already covers history).
- No packet/hex data (the `recorder` is the tool for that).
- No sample-rate change: `PeerDiagnostics` is a point-in-time read; the counters
  remain the authoritative "how often".

## Verifying it

- Unit: build the snapshot from a hand-set `directConn` (each `Path`/`State`
  combination), assert the fields (path, reason precedence, last error, ages).
- e2e (the container harness): after a run, `Status.PeerDiagnostics` names the
  peer with a plausible `Path`/`State`, and `grpcurl …/Status` returns it.

## Decisions (settled)

1. **`PeerDiagnostics` supersedes `PeerPunches`** — one per-peer map, not three.
   `p2p.Status` changes (in-process the map; the gRPC reply carries it as the
   repeated `peer_diagnostics` message), so every
   reader (`wisper`'s `/api/p2p`, the UI, tests) moves with it.
2. **`PeerAddr` is exposed in full; candidates as a count only.** The dialled
   endpoint is the peer's own; its announced address list is not enumerated.
3. **`LastRecvAge` comes from a per-frame atomic**, not a status-poll sample: a
   silent peer must be visible on the first status read, not only if the read
   happens to coincide with a frame.
4. **UI: a per-row expand on the peers page** — where a peer's state already
   lives — not a tooltip or a separate panel.

## Cost

- `p2p`: the three new fields + the snapshot builder + `Status` (and `PeerPunches`
  if superseded) + the proto message + the gRPC mapping + unit/e2e. One release.
- `plugin`: one proto release (the repeated message) + the `p2p` pin bump.
- `wisper`: the API passthrough + the peers-page detail + i18n.

## Follow-ups (assessed, not in this design)

From the same debugging-levers assessment. The last-frame age (originally a
separate idea) is folded into the snapshot above. Two more shipped on top of this
design (2026-09-30):

- **A bounded per-peer punch trace — shipped.** `directConn` carries a fixed ring
  of the last 16 punch steps (`noteRound` at the round's decision points:
  round start, the peer's candidate count, no shared family, the encryption gate,
  each family's dial/seed/smux result, `up`, and the backoff), reported as
  `PeerDiagnostic.Trace` and `PeerDiagnostic.trace` (proto field 15). A single
  snapshot cannot hold a flaky punch's history; the ring can, at fixed size and
  no per-round allocation.
- **A human-readable `p2p doctor [--peer <key>]` — shipped.** A separate CLI mode
  (`p2p doctor --addr <running host>`, read-only: it starts nothing), rendering
  identity, relay liveness, the aggregate summary, each peer's snapshot *and*
  trace, and a `verdicts:` section. The formatter is the shared `p2p/doctor`
  package — wisper serves the same report at `/api/p2p/doctor`, in-process, where
  the relay's liveness is read directly. Named `doctor`, not `status`: `status`
  is the raw gRPC RPC, this renders checks.

Still open:

- **Runtime fault injection.** The engine already has the test-only hooks (the
  relay double's `dropCtrl`/`dropData`/`dropPong`); expose equivalents behind an
  explicit opt-in config so a field failure can be reproduced locally. Cost:
  moderate; opt-in only, never on by default.
- **Attribute the fd/VPN teardown on Android.** One log naming the caller of
  `setTunFd(-1)` / `onRevoke` / release, so "who took the device" is answerable
  (finding it took a `debug.Stack()`).
- **Correlate a UI action with the backend.** The mutation middleware logs the
  request; carrying a per-action id from the UI into the p2p log would join the
  two layers. Cost: small.

Deliberately not doing: a full click-history recorder (narrow benefit, ships in
the product) and default packet capture (the `recorder` is the tool for that).
