# Fix: one-sided smux session rebuild wedge (p2p host)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the wedge where one side's relay smux session dies uncleanly (keepalive timeout) and rebuilds transparently over the surviving pair KCP, while the peer's stale session (with colliding stream IDs) silently swallows the re-presentation and never heals until a pair-level reset or restart.

**Architecture:** Add an out-of-band `ctrlSessionRebuilt` control frame (kind 0x06) riding the DERP control channel (independent of the smux/KCP byte stream, so it survives the smux death). On a *self-death* rebuild of an **active** relay session, the rebuilding side sends a sealed notice with a nonce. The peer, on receiving the notice, bounces its stale relay session (a cheap `killSession` with a new `reasonPeerRebuilt` that does NOT reset the pair KCP, punch, registration, direct underlay, or secure keys), then sends an ack after it rebuilds. The initiator, on receiving the ack, advances a per-peer `peerRebuildGen` and calls `notifyPeerSession`, so its links re-present onto the peer's fresh session. A freshness gate (relay-fresh within `relayLiveWindow`) prevents the notice from firing on watchdog/relay-idle self-deaths (which would disrupt direct-path fallback). Old peers ignore the unknown kind (forward-compatible).

**Tech Stack:** Go, `github.com/go-gost/p2p` module, `xtaci/smux` v1.5.57, DERP control frames, ChaCha20-Poly1305 sealed control payloads.

---

## File Structure

- Modify `internal/host/direct.go` — add `ctrlSessionRebuilt = 0x06` constant.
- Modify `internal/host/engine.go` — add `reasonPeerRebuilt`; add `peerRebuildGen`/`pendingNoticeNonce`/`sentNoticeNonce` to `peerConn`; add `pendingAckNonce`/`recvNoticeNonce` to `relayKCPPair`; handle control kind 0x06; send notice in `ensureSession` after a self-death rebuild of an active session; send ack after bounce rebuild; freshness gate.
- Modify `internal/host/relaykcp.go` — add `pendingAckNonce`/`recvNoticeNonce` fields to `relayKCPPair`.
- Modify `internal/host/udp.go` — `peerSessionGen` returns `max(sessionGen, peerRebuildGen)`.
- Add `internal/host/session_rebuild_notice_test.go` — regression test.

---

## Task 1: Add the control kind and reason (no behavior change)

**Files:**
- Modify: `internal/host/direct.go`
- Modify: `internal/host/engine.go`

- [x] **Step 1:** Add `ctrlSessionRebuilt = 0x06` to the control-kind const block in `direct.go`.
- [x] **Step 2:** Add `reasonPeerRebuilt sessionEndReason = "peer-rebuilt"` to the reason enum in `engine.go` (NOT added to `resetsPairKCP`, so the pair survives).
- [x] **Step 3:** Build: `go build ./...` — expect clean.

## Task 2: Add peer/pair state fields

**Files:**
- Modify: `internal/host/engine.go` (peerConn struct)
- Modify: `internal/host/relaykcp.go` (relayKCPPair struct)
- Modify: `internal/host/udp.go` (peerSessionGen)

- [x] **Step 1:** Add `peerRebuildGen atomic.Uint64`, `pendingNoticeNonce uint64`, `sentNoticeNonce uint64` to `peerConn`; add `buildRelayFresh bool`.
- [x] **Step 2:** Add `pendingAckNonce uint64`, `recvNoticeNonce uint64` to `relayKCPPair`.
- [x] **Step 3:** Update `peerSessionGen` in `udp.go` to return `max(sessionGen, peerRebuildGen)`.
- [x] **Step 4:** Build: `go build ./...`.

## Task 3: Write the failing (RED) regression test

**Files:**
- Add: `internal/host/session_rebuild_notice_test.go`

- [ ] **Step 1:** Write a test that:
  - Builds two engines via `newEncryptedPair(t)`.
  - Establishes sessions and opens S1 from A to B (SID 3), B accepts, bytes flow.
  - Forces A's one-sided self-death (`pair.newStream()` retire, per `TestSessionEndReportedWithoutKill` pattern) while S1 stays open (so SID 3 is still in B's table).
  - Waits for A's rebuild.
  - Opens S2 from A; asserts `B.Accept()` delivers within ~3s and bytes flow (today: SYN(SID 3) collides with B's stale SID 3 and is swallowed → timeout = RED).
  - Asserts B's session gen changed (bounce happened) and A's pair KCP session pointer unchanged (no heavy reset).
- [ ] **Step 2:** Run: `go test ./internal/host/ -run TestPeerSessionRebuiltNoticeRecovers -count=1` — expect FAIL (timeout) before implementation.

## Task 4: Implement the notice/ack protocol

**Files:**
- Modify: `internal/host/engine.go` (handleControl, ensureSession, sessionLocked)

- [ ] **Step 1:** `handleControl` case `ctrlSessionRebuilt`: unseal payload `[8B nonce][1B flag]`. On notice (flag 0): dedup via `pair.recvNoticeNonce`; set `pair.pendingAckNonce = nonce`; stamp `pair.lastRelayRecv = now`; `pc.killSession(..., reasonPeerRebuilt)` (bounce). On ack (flag 1): if `nonce == pc.sentNoticeNonce`, bump `pc.peerRebuildGen`, clear `sentNoticeNonce`, call `e.notifyPeerSession(src)`.
- [ ] **Step 2:** `sessionLocked`: detect `selfDeath := pc.sess != nil && pc.sess.IsClosed()`. After building, if `selfDeath && pc.buildRelayFresh`, set `pc.pendingNoticeNonce = pc.sessionGen.Load()`.
- [ ] **Step 3:** `ensureSession`: read `relayKCPFreshness` BEFORE `pc.mu.Lock()` (lock order: pair before adapter); set `pc.buildRelayFresh`. After `pc.mu.Unlock()`, if `pendingNoticeNonce != 0`, send sealed notice (flag 0) and record `sentNoticeNonce`. If `pair.pendingAckNonce != 0`, send sealed ack (flag 1) and clear.
- [ ] **Step 4:** Build: `go build ./...`.

## Task 5: Verify RED→GREEN

- [ ] **Step 1:** Run the new test: `go test ./internal/host/ -run TestPeerSessionRebuiltNoticeRecovers -count=1` — expect PASS.
- [ ] **Step 2:** Run the 3 direct-path tests that regressed: `go test ./internal/host/ -run 'TestDirectFallbackToRelay|TestDirectRepunchAfterMissedPeerGone|TestDirectV6FallbackToV4' -count=1` — expect PASS (freshness gate keeps notice off during relay-idle self-deaths).
- [ ] **Step 3:** Run full package: `go test ./internal/host/ -count=1 -timeout 600s` — expect all pass.

## Task 6: (Optional) Fix 2 — hub non-IP escalation

**Files:**
- Modify: `x/handler/tun/p2p.go` (and possibly `client.go`)

- [ ] **Step 1:** Assess feasibility of reaching the p2p engine from the hub handler (the hub image runs both). If feasible: escalate non-IP discards to a controlled pair rebuild with windowing/throttle/fuse per the calibrated design (strong shape → immediate; small-frame repeats → windowed; cooling + fuse). Otherwise, document as deferred.

## Task 7: (Optional) Fix 3 — relay-idle re-arm on pair-KCP bytes

- [ ] **Step 1:** Verify `sessionLocked` already calls `pair.rearmRelayIdle()` on every build (it does). Confirm the latch also rearms on inbound pair-KCP bytes; if not, add re-arm in the pump path. Likely already covered — mark done after code review.

---

## Notes

- **Deployment:** phone APK and hub image both need the new build for the notice path; partial rollout degrades to current behavior (unknown kind ignored).
- **Lock ordering:** `relayKCPFreshness` takes the pair lock; must be read before `pc.mu` (pair before adapter), mirroring `peerRelaySessionEnded`.
- **No loops:** acks never trigger bounces; only self-death rebuilds send notices. Cross-deaths (both sides self-die) remain bounded.
- **Verification evidence:** full suite must pass before claiming done; report any unrelated failures by name.