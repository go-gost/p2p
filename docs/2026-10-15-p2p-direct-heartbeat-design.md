# Direct-path heartbeat (sticky direct) — design

Date: 2026-10-15. Status: draft, awaiting review.
Scope: `p2p/internal/host` only. Reverses one H3 rule from
`2026-10-05-p2p-kcp-path-migration-design.md` (no warm standby).

## 1. Problem

Once a direct underlay is installed, the pair retires it after 6s without
inbound KCP traffic (`directUnderlayIdle`), even when the path is perfectly
healthy. An idle peer therefore flaps direct↔relay forever (~6.6s period,
live-observed 2026-10-14 on vscode-docker and the probe-spoke: seed ok →
`retired reason=idle` → re-punch → repeat, 131 migrations / 130 fallbacks in
40 min). The badge flips, and every re-punch burns STUN + relay control
traffic for no reason.

Root confusion: "no recent inbound" is read as "unhealthy". For an idle peer
there is no traffic to be recent, so a healthy path is indistinguishable from
a dead one — unless the path is probed explicitly.

## 2. Principle (user decision, 2026-10-15)

Direct-first, relay-second: **once a direct path is established and proven,
it stays regardless of idleness; fallback to relay happens only when the
direct path is proven dead.** The relay RTT / smux keepalive cannot prove
direct health — they ride the currently preferred path (session-level, not
path-level). So the proof must be packets on the direct socket itself.

Non-goals: no change to punch/seed, candidate exchange, backoff, or the
relay watchdog. No per-path KCP. No config knob (constants, test-tunable).

## 3. Design

### 3.1 Heartbeat token (per underlay)

- At registration (`newDirectUnderlayToken`), draw a random 8-byte `hbToken`,
  distinct from the seed `localToken` and non-zero. No entropy → no heartbeat
  (`hasHb=false`); the old idle semantics apply unchanged.
- A heartbeat is a seed-magic (`"P2PS"`) packet carrying `hbToken`. It reuses
  the seed wire format so no new framing is needed and `readFrom` already
  skips magic packets (never delivered to KCP).

### 3.2 Echo rules (no ping-pong)

On receipt of a magic packet with a full token, in order:

1. token == own `hbToken` → **our own echo coming back: record
   `lastHbRecv=now`, never re-echo.**
2. token == own `localToken` → own seed echo (existing H2 guard): never echo.
3. otherwise → peer's probe/heartbeat: echo back to source (existing behavior).

Each side's tokens are independent random draws, so rule 1 fires only for
one's own echo and rule 3 answers the peer. A late seed handshake is
unaffected (seed tokens still echo as before).

### 3.3 Pump behavior (`pumpDirect` silence tick, 1s granularity)

On each silence tick:

1. If silent for ≥ `directHeartbeatInterval` (3s) with no inbound datagram,
   send one heartbeat (max ~1/s; keeps NAT bindings warm as a side effect).
2. If `hbLive()` (echo seen within `directUnderlayIdle`):
   re-arm `lastDirectRecv=now` while this underlay is still installed —
   the session keeps preferring it, no path-change event (nothing changed).
3. Else fall through to the existing `reportDirectIdle` path (fires once per
   episode): engine retires + re-punches as today.

Net effect on thresholds (defaults): healthy path heartbeats at 3s/4s/5s and
never idles; a dead path sends unanswered heartbeats and retires at 6s, same
as today. Underlays without a token (`newDirectUnderlay`, tests) behave
exactly as before.

### 3.4 What "sticky" does and does not change

- `preferredDirectLocked`, `WriteTo`, KCP migration: untouched. They key off
  `lastDirectRecv`, which heartbeats now keep fresh — so a live direct path
  stays preferred and carries KCP (including its keepalives), which in turn
  refreshes recency from real traffic.
- Idle retire (`direct-idle` → backoff → re-punch) still exists, but only
  fires for paths whose heartbeats go unanswered: i.e. actually dead paths.
- Relay stays up throughout as fallback; relay watchdog untouched.

## 4. Observability

- `hbLive()` gates retirement; expose heartbeat counters on the underlay
  (`hbSent`/`hbRecv`, atomic) and surface them in `Status`/doctor per-peer
  (so "direct up, last traffic 7s" becomes explainable: heartbeats live).
- Existing events unchanged: `seed`, `path-change`, `direct-underlay`
  (`installed`/`retired reason=idle|replaced`).

## 5. Tests (TDD, all in `internal/host`)

1. `TestSeedHandshakeReportsAnswerSource` (done, green): seed reports the
   answering source so registration follows the completed path.
2. `TestDirectHeartbeatKeepsIdlePath` (written): two token underlays over
   loopback, one installed, zero KCP traffic past 3× idle → `onDirectIdle`
   never fires, underlay still installed and preferred. (Shrinks
   `directUnderlayIdle`/`directHeartbeatInterval` together, following the
   existing 150ms test precedent.)
3. `TestDirectHeartbeatDeadPathRetires`: far end stops echoing (close its
   socket) → idle fires once, engine path retires as today.
4. `TestDirectHeartbeatNoPingPong`: both ends heartbeat; echo counters settle
   (extends the `TestDirectUnderlaySeedEchoQuiesces` pattern).
5. Full package suite green except pre-existing sandbox failures
   (`TestDirectV6FallbackToV4` — no IPv6 here, fails on pristine tree too;
   `TestDirectPunchStaggeredStart` — load-flaky on pristine tree too).

## 6. Rollout / verification

1. Land behind no flag (behavior is self-protecting: dead paths still retire
   at 6s).
2. Re-run the probe-spoke experiment: idle spoke must hold `direct path up`
   with `session age` growing and zero migrations; `ping -i 5` must stay on
   direct with stable RTT (no more 6s/avg-1s KCP-retransmit pattern).
3. Then the p2p tag → wisper bump → hub redeploy path already used for v0.14.5.

## 7. Risks

- Heartbeat adds ~1 small packet/s/direction per idle direct peer: negligible
  vs a re-punch storm (STUN + candidates + seed every ~11s today).
- A path that passes heartbeats but drops KCP-sized packets (MTU blackhole)
  would look live while losing data — accepted: today's code has the same
  blind spot (seed ok ≠ data flows), and KCP retransmit over relay still
  covers it. Future work, not this spec.
- `markUp` must register the seed-learned source, not the dialed candidate
  (companion fix, same release): otherwise both ends' heartbeats go to a
  stale address and every path reads dead.
