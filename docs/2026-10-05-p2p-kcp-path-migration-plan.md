# p2p KCP Path Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each peer one long-lived KCP session whose packet path can switch between the DERP relay and a hole-punched direct UDP path, so streams already open at cutover migrate transparently and fall back automatically.

**Architecture:** Generalize `relayKCPPair` (one KCP session per peer, `ownConn=false`) into a dual-read, single-send holder: a relay pump and an optional direct pump both feed one fan-in channel; `WriteTo` picks the path that most recently carried inbound traffic. The direct path is established by the existing punch, whose KCP+secure+smux tail is replaced by a raw-UDP seed handshake followed by registering the punched socket as the pair's direct underlay. The separate direct KCP session, direct secure session, and direct smux are retired.

**Tech Stack:** Go, `github.com/xtaci/kcp-go/v5` (v5.6.72, no migration API), `github.com/xtaci/smux`, `net`, `net/netip`, `sync/atomic`.

**Spec:** `p2p/docs/2026-10-05-p2p-kcp-path-migration-design.md`

## Global Constraints

- Work in the `p2p` module; it is its own Go module. Run tests with `GOWORK=off CGO_ENABLED=1` and `-p 1`.
- Toolchain: `go` is at `/root/.local/go/bin`. Prepend `export PATH="$PATH:/root/.local/go/bin:/root/go/bin"` if `go` is not found.
- Unit-test root: `cd p2p && ... go test ... ./internal/host/`.
- KCP session tuning: `relayConv(pub, peer)`, `kcp.NewConn4(conv, dummyAddr{}, nil, 0, 0, false, pair)`, `SetNoDelay(1, 10, 2, nc)`, `SetMtu(1400)`, `SetWindowSize(256, 256)`, `block=nil`. `nc` is set **per preferred path**: `1` on relay (relay's bounded-queue rationale) and `0` on direct (public-Internet congestion path) — see Task 14.
- The pair's `ReadFrom` MUST return the **zero-value** `dummyAddr{}` (`String() == "derp"`) on every path, matching the `remote` passed to `kcp.NewConn4`. Returning `dummyAddr{peer}` (`String() == "derp:<key>"`) makes kcp-go's `defaultReadLoop` silently drop every packet.
- smux keepalive is `smuxKeepAliveInterval = 3s` / `smuxKeepAliveTimeout = 15s`; `directUnderlayIdle = 6s` (2 × interval).
- Do NOT change the relay secure **protocol/mechanism** (`secureSessionLocked`, `dropRelaySecure`, `resetPeerSession`). The pair keeps `secureTransportRelay` (`0x00`). The ONE sanctioned exception is Task 0's conditional relay-loss reset (H1): it only changes *when* sessions are dropped, never the wire protocol or key derivation.
- Lockstep upgrade only: no mixed-version compatibility, no capability gating.
- `E2E` lives in `p2p/tests/e2e` and needs Docker; run it last.
- **Do not run the `git commit` steps unless the user has explicitly authorized commits** (project convention: no auto-commit). When unauthorized, the step means "leave the working tree clean and report".
- Keep `internal/host/spike_kcpmigrate_test.go` permanently as reproducible evidence (spec decision); Task 5 adds the product test alongside it (do not delete the spike).

## Review Focus

These are the failure modes the design implies but no single task's happy-path test exercises. Each is pinned by a test named in the owning task.

1. Inbound direct datagrams from an address other than the punched peer address (spoofing, stale NAT mapping) must be dropped before reaching KCP. (Task 1)
2. Seed packets and KCP packets may share the socket while one peer has registered and the other is still seeding; neither may corrupt the KCP session. (Task 1 + Task 7)
3. A relay endpoint swap (relay reconnect) while direct is preferred must not disturb the direct underlay or stall reads, and must not send on the retired relay endpoint. (Task 2 + Task 4)
4. Both underlays going dead must surface as a pair `io.EOF` (so smux rebuilds) with no leaked direct pump goroutine or open socket. (Task 4 + Task 7)
5. A re-punch that registers a new direct underlay while an old one is still registered must retire the old socket exactly once and never double-read. (Task 7)
6. Relay link loss / peer-gone while a direct underlay is live must NOT tear down the pair, secure session, or KCP epoch; with no direct it must reset exactly as today. (Task 0)
7. After one side registers, a late seed echo must still complete the peer's seed (symmetric success), never a one-sided commit. (Task 1)
8. The idle watchdog must not deadlock or leak: clearing a direct underlay from its own pump callback must not wait on that pump. (Task 4 + Task 7)
9. A direct underlay that dies shortly after registration must back off (no flap storm), and KCP congestion control must be off only on the relay path. (Task 7 + Task 14)

---

### Task 1: `directUnderlay` transport

**Files:**
- Create: `p2p/internal/host/directunderlay.go`
- Test: `p2p/internal/host/directunderlay_test.go`

**Interfaces:**
- Consumes: nothing (leaf type).
- Produces:
  - `type directUnderlay struct{ ... }`
  - `func newDirectUnderlay(sock *net.UDPConn, peer netip.AddrPort) *directUnderlay`
  - `func (u *directUnderlay) name() string` → `"direct"`
  - `func (u *directUnderlay) readFrom(p []byte) (int, error)` — blocks; drops packets whose source is not `u.peer`; on a packet prefixed with `seedProbeMagic` it **echoes it back** to `u.peer` (late seed responder) and continues (never returns it to KCP); returns `io.EOF` after `close`.
  - `func (u *directUnderlay) writeTo(p []byte) (int, error)` — `WriteToUDP` to `u.peer`; swallows errors, always returns `(len(p), nil)`.
  - `func (u *directUnderlay) close() error` — idempotent; closes `u.sock`.
  - `var seedProbeMagic = [4]byte{0x50, 0x32, 0x50, 0x53}` (`"P2PS"`).

- [ ] **Step 1: Write the failing tests**

In `directunderlay_test.go`, with two loopback `*net.UDPConn`s `a` and `b` (`a` is the underlay, dialing `b`):

```go
func TestDirectUnderlayFiltersForeignSource(t *testing.T) {
    // a is the underlay; b is the peer; c is a third socket.
    // Send "fromB" from b to a's local addr, then "fromC" from c.
    // Read on the underlay: first read must be exactly "fromB".
    // Then assert a subsequent read with a 200ms deadline times out
    // (the "fromC" datagram was dropped, not returned).
}

func TestDirectUnderlayEchoesSeedMagic(t *testing.T) {
    // b sends seedProbeMagic + "x", then "kcp".
    // The underlay's first read must be exactly "kcp" (the seed packet is
    // not returned to KCP), and b must receive seedProbeMagic + "x" back.
}

func TestDirectUnderlayWriteGoesToPeer(t *testing.T) {
    // underlay.writeTo([]byte("hello")); read on b; got == "hello".
}

func TestDirectUnderlayReadEOFAfterClose(t *testing.T) {
    // close() then readFrom returns io.EOF (deadline 1s guard).
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestDirectUnderlay ./internal/host/ -v`
Expected: FAIL / build error: `undefined: newDirectUnderlay`.

- [ ] **Step 3: Implement `directUnderlay`**

`readFrom` loops: set a 1s read deadline on `u.sock`; `n, src, err := u.sock.ReadFromUDP(p)`; on timeout continue (allows periodic `close` observation — also select on a `u.done` channel closed by `close`); if `!src.AddrPort().Addr().Unmap().Compare(u.peer.Addr().Unmap())` (or literal `src.AddrPort() != u.peer`, see note) continue; if `bytes.HasPrefix(p[:n], seedProbeMagic[:])` echo it back (`u.sock.WriteToUDP(p[:n], u.peer)`, ignore the write error) and continue; return `n, nil`. On `close`, return `io.EOF`.

Note: compare on `AddrPort` after `Unmap()` on both sides so a v4-mapped peer address matches.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestDirectUnderlay ./internal/host/ -v`
Expected: PASS (all four).

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/directunderlay.go p2p/internal/host/directunderlay_test.go
git commit -m "feat(p2p): add direct UDP underlay with source and seed filtering"
```

---

### Task 2: Pair fan-in over a relay pump (behavior-preserving)

**Files:**
- Modify: `p2p/internal/host/relaykcp.go`
- Test: `p2p/internal/host/relaykcp_test.go` (existing suite is the regression)

**Interfaces:**
- Consumes: existing `relayPacketConn`, `register`, `wake`.
- Produces:
  - `relayKCPPair` gains `recv chan []byte` (buffered, e.g. 256) and `done chan struct{}`.
  - `func newRelayKCPPair(...)` initializes `recv` and `done` and starts `go p.pumpRelay()`.
  - `func (p *relayKCPPair) readRelay(p []byte) (int, net.Addr, error)` — the current `ReadFrom` body (ep wait/wake loop, io.EOF only at pair end), renamed.
  - `func (p *relayKCPPair) pumpRelay()` — loops `readRelay`, copies any `n>0` into `p.recv` (select on `p.done`), exits on error.
  - `func (p *relayKCPPair) ReadFrom(b []byte) (int, net.Addr, error)` — now selects on `p.recv` and `p.done`; on `done`, drains one buffered `recv` packet then returns `io.EOF`; returns `dummyAddr{}`.

- [ ] **Step 1: Write the failing test**

```go
func TestPairReadFromFanInReturnsDummyAddr(t *testing.T) {
    // Build e/pair as relaykcp_test.go does; register a peerConn;
    // push a packet to pc.inbound; pair.ReadFrom must return it
    // with addr.String() == "derp" (the zero dummyAddr).
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestPairReadFromFanIn ./internal/host/ -v`
Expected: FAIL (missing `recv`/`pumpRelay`).

- [ ] **Step 3: Implement the fan-in**

Move the current `relayKCPPair.ReadFrom` body verbatim into `readRelay`; add `pumpRelay` and the new `ReadFrom`. `shutdown` records `closed` and closes `wake` (existing) and `p.done`; ensure `p.done` is closed exactly once (guard with `closed`).

- [ ] **Step 4: Run the full relay KCP suite**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestRelay|TestPair' ./internal/host/ -v`
Expected: PASS, including the pre-existing `relaykcp_test.go` tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/relaykcp.go p2p/internal/host/relaykcp_test.go
git commit -m "refactor(p2p): feed relay datagrams through a pair pump"
```

---

### Task 3: Dual-read and preferred-path selection

**Files:**
- Modify: `p2p/internal/host/relaykcp.go`
- Test: `p2p/internal/host/relaykcp_test.go`

**Interfaces:**
- Consumes: Task 1 `directUnderlay`, Task 2 `recv`/`done`/`pumpRelay`.
- Produces:
  - `func (p *relayKCPPair) setDirectUnderlay(u *directUnderlay)` — retires any existing underlay, installs `u`, starts `go p.pumpDirect(u)`, seeds `p.lastDirectRecv` to now.
  - `func (p *relayKCPPair) clearDirectUnderlay()` — stops the direct pump and closes the socket exactly once; idempotent.
  - `func (p *relayKCPPair) pumpDirect(u *directUnderlay)` — loops `u.readFrom`, updates `p.lastDirectRecv`, copies into `p.recv` (select on `p.done` and a per-underlay stop channel), exits on error/close.
  - `func (p *relayKCPPair) preferredDirect() bool` — true iff a direct underlay is installed and `time.Since(lastDirectRecv) < directUnderlayIdle`.
  - `func (p *relayKCPPair) pathName() string` — `"direct"` when `preferredDirect()`, else `"relay"`.
  - `const directUnderlayIdle = 6 * time.Second`
  - `WriteTo` picks: if `preferredDirect()` write the direct underlay, else the relay `ep`; still returns `(len(b), nil)` and counts `bytesSent` (add a `bytesDirectSent`/`bytesRelaySent` split if cheap, else leave `bytesSent`).

- [ ] **Step 1: Write the failing tests**

```go
func TestPairPreferredFollowsInboundRecency(t *testing.T) {
    // Install a direct underlay; preferredDirect() == true.
    // Force lastDirectRecv into the past (> directUnderlayIdle); preferredDirect() == false.
    // Deliver one direct packet; preferredDirect() == true again.
}

func TestPairWriteToUsesPreferredPath(t *testing.T) {
    // With direct preferred, WriteTo lands on the direct socket (peer reads it),
    // not on the relay peerConn send.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestPairPreferred|TestPairWriteTo' ./internal/host/ -v`
Expected: FAIL (undefined methods).

- [ ] **Step 3: Implement dual-read and preferred selection**

Guard `p.direct` with `p.mu`. `pumpDirect` uses a per-underlay `stop chan struct{}` owned by the pair; `clearDirectUnderlay` closes `stop` and calls `u.close()` once.

- [ ] **Step 4: Run to verify they pass, plus the existing suite**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestRelay|TestPair|TestDirect' ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/relaykcp.go p2p/internal/host/relaykcp_test.go
git commit -m "feat(p2p): dual-read pair session with recency-preferred send path"
```

---

### Task 4: Direct idle watchdog, fallback, and pair EOF

**Files:**
- Modify: `p2p/internal/host/relaykcp.go`
- Test: `p2p/internal/host/relaykcp_test.go`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `func (p *relayKCPPair) onDirectIdle func(*directUnderlay)` — optional callback set by the engine; invoked (outside `p.mu`) when `pumpDirect` observes `time.Since(lastDirectRecv) >= directUnderlayIdle`.
  - `pumpDirect` on idle: call `p.onDirectIdle(u)` once per idle episode (re-arm when a packet arrives again), do **not** itself clear the underlay (the engine decides and calls `clearDirectUnderlay`).
  - `ReadFrom` returns `io.EOF` when `p.done` is closed after draining, so kcp-go's read loop ends and smux sees the pair end.

- [ ] **Step 1: Write the failing tests**

```go
func TestPairDirectIdleFiresCallbackOnce(t *testing.T) {
    // Install direct underlay with a short-lived override of the idle bound
    // (make the bound a var or inject it), deliver one packet, then go silent.
    // onDirectIdle fires exactly once; a second packet re-arms it.
}

func TestPairCloseReturnsEOF(t *testing.T) {
    // Install both underlays, then shutdown(); a blocked ReadFrom returns io.EOF;
    // the direct pump has exited (no goroutine leak: check with runtime.NumGoroutine
    // before/after with a bounded settle).
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestPairDirectIdle|TestPairClose' ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement the watchdog and EOF**

Keep `directUnderlayIdle` overridable in tests by making the pair read a package-level `var directUnderlayIdle = 6 * time.Second` (tests may set it and restore). `shutdown` closes `p.done`; `pumpRelay`/`pumpDirect` select on it.

- [ ] **Step 4: Run to verify they pass**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestPair|TestRelay|TestDirect' ./internal/host/ -v`
Expected: PASS, race-clean.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/relaykcp.go p2p/internal/host/relaykcp_test.go
git commit -m "feat(p2p): detect a silent direct underlay and fall back to relay"
```

---

### Task 5: Promote the spike to a product migration test

**Files:**
- Create: `p2p/internal/host/pairmigrate_test.go`
- Keep: `p2p/internal/host/spike_kcpmigrate_test.go` (reproducible evidence; do not delete)
- Test: `p2p/internal/host/pairmigrate_test.go`

**Interfaces:**
- Consumes: Task 3 `setDirectUnderlay`/`clearDirectUnderlay`/`preferredDirect`, Task 1 `directUnderlay`.
- Produces: no production code; the product-level guarantee test.

- [ ] **Step 1: Write the test (adapt the spike model)**

Reuse the spike's `spikeMedium`/`spikeSwitchConn` **as test scaffolding only if still needed**; prefer building two real `kcp.NewConn4(..., ownConn=false, pair)` sessions whose pairs are flipped through a fault-injecting `directUnderlay`. Keep the three assertions: (a) 8 MiB byte stream exact across a relay→direct flip with a 200 ms black hole, reorder, and duplication; (b) 4 MiB through smux over the same pair across the flip; (c) negative control: without dual-read the session stalls.

```go
func TestPairMigrationByteStream(t *testing.T) { ... }
func TestPairMigrationSmux(t *testing.T) { ... }
func TestPairMigrationRequiresDualRead(t *testing.T) { ... }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -count=3 -run TestPairMigration ./internal/host/ -v -timeout 300s`
Expected: FAIL to build until the scaffolding is wired to the pair.

- [ ] **Step 3: Wire the test to the product pair**

Flips are driven by `pair.setDirectUnderlay` with a direct underlay whose socket is a loopback UDP socket the test can black-hole/duplicate/reorder via an intermediate relay goroutine.

- [ ] **Step 4: Run to verify they pass**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -count=3 -run TestPairMigration ./internal/host/ -v -timeout 300s`
Expected: PASS, race-clean, 3 iterations.

- [ ] **Step 5: Keep the spike and commit**

Per the spec decision, `spike_kcpmigrate_test.go` is retained as reproducible evidence; the product test is added alongside it (do NOT `git rm` the spike).

```bash
git add p2p/internal/host/pairmigrate_test.go p2p/internal/host/spike_kcpmigrate_test.go
git commit -m "test(p2p): pin lossless KCP path migration at the pair level"
```

---

### Task 6: Raw-UDP seed handshake

**Files:**
- Modify: `p2p/internal/host/direct.go`
- Test: `p2p/internal/host/direct_test.go`

**Interfaces:**
- Consumes: Task 1 `seedProbeMagic`.
- Produces:
  - `func seedHandshakeUDP(sock *net.UDPConn, peer netip.AddrPort, timeout time.Duration) error` — symmetric token echo over raw UDP: send `seedProbeMagic || token` to `peer` every ~200 ms; on receiving `seedProbeMagic || peerToken`, remember it and echo `seedProbeMagic || peerToken` back; succeed when our own token is echoed; return an error on timeout.
  - `const seedRetransmit = 200 * time.Millisecond`

- [ ] **Step 1: Write the failing tests**

```go
func TestSeedHandshakeUDPRoundTrip(t *testing.T) {
    // Two loopback UDPConns; run seedHandshakeUDP on each with the other's addr.
    // Both return nil within 2s.
}

func TestSeedHandshakeUDPTimesOut(t *testing.T) {
    // One side runs alone; returns a non-nil error after the timeout.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestSeedHandshakeUDP ./internal/host/ -v`
Expected: FAIL (undefined).

- [ ] **Step 3: Implement `seedHandshakeUDP`**

Mirror the existing `seedHandshake` semantics; read with a short deadline to interleave retransmits; ignore packets without `seedProbeMagic`.

- [ ] **Step 4: Run to verify they pass**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestSeedHandshakeUDP ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/direct.go p2p/internal/host/direct_test.go
git commit -m "feat(p2p): raw-UDP seed handshake for the direct underlay"
```

---

### Task 7: Register and retire the direct underlay

**Files:**
- Modify: `p2p/internal/host/engine.go`, `p2p/internal/host/direct.go`
- Test: `p2p/internal/host/direct_test.go`

**Interfaces:**
- Consumes: Task 3/4 pair methods, Task 1 `directUnderlay`.
- Produces:
  - `func (e *engine) registerDirectUnderlay(peer derpclient.PublicKey, sock *net.UDPConn, addr netip.AddrPort, token [seedTokenLen]byte)` — builds a `directUnderlay` via `newDirectUnderlayToken(sock, addr, token)`, installs it on `e.relayKCPPairFor(peer)`, and sets the pair's `onDirectIdle` to `func(u *directUnderlay){ e.directUnderlayDead(peer, u) }` (idempotent per pair). The token MUST be threaded from the handshake (Task 6) so the underlay echoes peer probes; the no-token constructor never echoes.
  - `func (e *engine) directUnderlayDead(peer derpclient.PublicKey, u *directUnderlay)` — if the pair still holds `u`, `clearDirectUnderlay()`, close the socket, mark `directConn` down, and `dc.start()` (re-punch).
  - `directConn`: replace `sess *smux.Session` with `sock *net.UDPConn`; drop `secure`; `markUp(sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte)` stores them, sets `state=directUp`, and calls `e.registerDirectUnderlay(peer, sock, peerAddr, token)`; `markDead` (`direct.go:797`) becomes the underlay-death handler.
  - `func (dc *directConn) isUp() bool` and `func (dc *directConn) peerAddrString() string` keep `peerTransports`/`OpenStream` reporting working.

- [ ] **Step 1: Write the failing tests**

```go
func TestRegisterDirectUnderlayInstallsOnPair(t *testing.T) {
    // Fake engine with a pair; register; pair.preferredDirect() == true.
}

func TestDirectUnderlayDeadClearsAndRepunches(t *testing.T) {
    // register, then directUnderlayDead; pair.preferredDirect() == false;
    // dc.state returns to directNone or directAttempting (re-punch started).
}

func TestRegisterDirectUnderlayRetiresOldSocket(t *testing.T) {
    // register sock1, register sock2; sock1 is closed exactly once;
    // reading on the pair never returns sock1 packets.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestRegisterDirectUnderlay|TestDirectUnderlayDead' ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement registration, retirement, and the `directConn` state change**

`directConn.session()`/`live()`/`detachSessionLocked` are rewritten for the socket-backed state. `markUp` keeps its stats increments (`punchSuccess`, `ups`).

- [ ] **Step 4: Run to verify they pass**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestRegisterDirectUnderlay|TestDirectUnderlayDead|TestDirect' ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/engine.go p2p/internal/host/direct.go p2p/internal/host/direct_test.go
git commit -m "feat(p2p): register the punched socket as the pair direct underlay"
```

---

### Task 8: Rewrite the punch tail; delete the direct plane

**Files:**
- Modify: `p2p/internal/host/direct.go`, `p2p/internal/host/engine.go`
- Test: `p2p/internal/host/direct_test.go`

**Interfaces:**
- Consumes: Task 6 `seedHandshakeUDPToken`, Task 7 `registerDirectUnderlay`.
- Produces: the punch's per-family loop (`direct.go:1202-1290`) ends with `token, err := seedHandshakeUDPToken(sock, dial, timeout)` + `markUp(sock, dial, token)` instead of KCP/secure/smux. Deleted: `kcp.NewConn4(dc.conv(), ...)`, `dc.secure.settled()` gate, `dc.secure.conn()`, `faultConn` on the direct path, `directSmuxConfig`, the direct `smux.Client`/`smux.Server`, and the direct `acceptLoop` call.

- [ ] **Step 1: Write the failing tests**

```go
func TestPunchRegistersUnderlay(t *testing.T) {
    // Two engines with a fake relay/candidate exchange (as existing punch tests do);
    // after a successful round, the pair's preferredDirect() is true.
}

func TestPunchRefusedWhenRelayDown(t *testing.T) {
    // Existing behaviour: no relay means no candidate exchange, no underlay.
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestPunchRegistersUnderlay ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Rewrite the punch tail**

Keep STUN, candidates, `fams`, family order, `backoff`, `retry`, `onCandidates`. Replace the tail as specified. Update every existing punch test that constructs `directConn{sess: ...}` or asserts `dc.session()` to the socket-backed model.

- [ ] **Step 4: Run the direct suite**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestDirect|TestPunch|TestSeed' ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/direct.go p2p/internal/host/engine.go p2p/internal/host/direct_test.go
git commit -m "refactor(p2p): punch registers a direct underlay instead of a direct session"
```

---

### Task 9: Remove the direct secure session

**Files:**
- Modify: `p2p/internal/host/direct.go`, `p2p/internal/host/engine.go`
- Test: `p2p/internal/host/engine_test.go`, `p2p/internal/host/secure_test.go`

**Interfaces:**
- Consumes: Task 8 (no direct KCP remains).
- Produces: delete `directConn.secure` construction (`direct.go:237`), remove `rekeyIfUsed` (`direct.go:1085`) and its only caller, remove the `secureTransportDirect` branch of `handleControl` (`engine.go:1446-1487`) and `resetDirectSession` (`engine.go:1544`). `secureTransportDirect` and `secure.go`'s tag stay defined (relay keeps `secureTransportRelay`), or are removed if no reference remains — pick whichever compiles with the smaller diff.

- [ ] **Step 1: Write the failing test**

```go
func TestDirectPlaneHasNoSecureSession(t *testing.T) {
    // After a punch, the peer's secure map contains only the relay entry;
    // no secureTransportDirect session is ever created.
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestDirectPlaneHasNoSecureSession ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Delete the direct secure constructs**

Remove the symbols listed above; fix compilation fallout in `secure.go`/`engine.go`. Do not touch `secureSessionLocked`, `dropRelaySecure`, or `resetPeerSession`.

- [ ] **Step 4: Run the secure and engine suites**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestSecure|TestEngine|TestDirect' ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/direct.go p2p/internal/host/engine.go p2p/internal/host/secure.go
git commit -m "refactor(p2p): drop the separate direct secure session"
```

---

### Task 10: Simplify `OpenStream` and the accept loop

**Files:**
- Modify: `p2p/internal/host/engine.go`
- Test: `p2p/internal/host/engine_test.go`

**Interfaces:**
- Consumes: Task 7 `directConn.isUp`, Task 3 `pathName`.
- Produces:
  - `func (e *engine) OpenStream(peerB64 string) (net.Conn, error)` opens only on the relay pair: `pc := e.peerConn(peer); sess, err := pc.ensureSession(true, true); c, err := openStream(sess, to)`; returns `&openedStream{Conn: c, transport: e.pairPath(peer)}`. It may call `e.maybeStartDirect(peer)` (non-blocking) for eagerness. The direct/punch branches are removed.
  - `func (e *engine) pairPath(peer derpclient.PublicKey) string` — `"direct"` or `"derp"`, from the pair's `pathName()`.
  - The direct `acceptLoop` call is gone; only the relay pair's accept loop remains.

- [ ] **Step 1: Write the failing test**

```go
func TestOpenStreamUsesPairAndReportsPath(t *testing.T) {
    // Open a stream before a punch: transport reports "derp" and data flows.
    // Install a direct underlay on the pair: a newly opened stream reports "direct".
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestOpenStreamUsesPair ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Simplify**

Remove the direct/direct-punch branches from `OpenStream`. Ensure the punch is still triggered on peer discovery by `maybeStartDirect` from the pump (unchanged) and add the non-blocking call in `OpenStream`.

- [ ] **Step 4: Run the engine suite**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run 'TestOpenStream|TestEngine|TestSession' ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/engine.go p2p/internal/host/engine_test.go
git commit -m "refactor(p2p): open every stream on the pair session"
```

---

### Task 11: Path reporting in status and diagnostics

**Files:**
- Modify: `p2p/internal/host/engine.go`, `p2p/internal/host/direct.go`
- Test: `p2p/internal/host/engine_test.go`

**Interfaces:**
- Consumes: Task 3 `pathName`, Task 7 `directConn.isUp`.
- Produces: `peerTransports`/`PeerTransports` and `relayKCPSnapshot` report the pair's current path (`direct` vs `derp`) and per-underlay byte counters. Keep the existing `transportDirect`/`transportRelay` string values so Status consumers do not change.

- [ ] **Step 1: Write the failing test**

```go
func TestPeerTransportsReportsPairPath(t *testing.T) {
    // No direct underlay -> "derp"; install one -> "direct".
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestPeerTransportsReportsPairPath ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement the reporting**

Reuse `relayKCPStats`/`relayKCPSnapshotAttrs`; add the direct counters if the struct already has room, otherwise leave them out and report only the path (YAGNI).

- [ ] **Step 4: Run to verify it passes**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestPeerTransports ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/engine.go p2p/internal/host/direct.go p2p/internal/host/engine_test.go
git commit -m "feat(p2p): report the pair's current path in status"
```

---

### Task 12: Relocate fault injection to the pair write path

**Files:**
- Modify: `p2p/internal/host/faults.go` (as needed), `p2p/internal/host/relaykcp.go`
- Test: `p2p/internal/host/faults_test.go`

**Interfaces:**
- Consumes: Task 3 `WriteTo`.
- Produces: the "mute data" fault applies to the pair's `WriteTo` (all underlays), replacing the old `faultConn` wrapper that only wrapped the direct KCP underlay. Read `p2p/docs/2026-09-30-p2p-fault-injection-plan.md` first and preserve the documented fault kinds and their observable behavior.

- [ ] **Step 1: Write the failing test**

```go
func TestFaultMuteDataStallsThenRecovers(t *testing.T) {
    // Enable muteData on a peer's pair, stream, assert the reader stalls;
    // clear it, assert the stream completes byte-exact (KCP retransmits).
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestFaultMuteData ./internal/host/ -v`
Expected: FAIL.

- [ ] **Step 3: Move the fault hook**

Keep `sendControl` faulting as-is; move the data fault from `faultConn` to `relayKCPPair.WriteTo` (or a small wrapper around it) so it applies regardless of the preferred underlay. Delete the now-unused `faultConn` on the direct path.

- [ ] **Step 4: Run the faults suite**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 -run TestFault ./internal/host/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/internal/host/faults.go p2p/internal/host/faults_test.go p2p/internal/host/relaykcp.go
git commit -m "refactor(p2p): apply data faults at the pair write path"
```

---

### Task 13: End-to-end scenarios and memory

**Files:**
- Modify: `p2p/tests/e2e/` (the `derp-direct` and `udp-tun` scenarios)
- Modify: `.memory/notes/p2p-kcp-session-migration.md`, `.memory/MEMORY.md`
- Test: `p2p/tests/e2e`

**Interfaces:**
- Consumes: all of the above.
- Produces: an e2e that opens a stream before the punch, waits for the direct path, and asserts the same stream completes byte-exact after migration (read the preferred path from Status).

- [ ] **Step 1: Add the migration assertion to the e2e scenarios**

Extend `derp-direct` and `udp-tun` to (a) start a transfer while relay-only, (b) wait until Status reports `direct`, (c) finish the transfer and compare bytes. Skip cleanly when Docker is unavailable, matching the existing harness.

- [ ] **Step 2: Run the e2e suite**

Run: `cd p2p/tests/e2e && GOWORK=off go test -v ./...`
Expected: PASS (or a documented Docker-unavailable skip).

- [ ] **Step 3: Update memory**

Rewrite `.memory/notes/p2p-kcp-session-migration.md` with the shipped design (one pair session, dual underlay, recency fan-in, raw-UDP seed), and adjust the `[[wikilinks]]` index line in `.memory/MEMORY.md`. Note the retired direct plane and the `dummyAddr{}` gotcha.

- [ ] **Step 4: Run the whole module**

Run: `cd p2p && GOWORK=off CGO_ENABLED=1 go test -race -p 1 ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add p2p/tests/e2e .memory
git commit -m "test(p2p): cover relay-to-direct migration end to end"
```

---

## Self-Review

**Spec coverage:** Architecture (Tasks 2–4), direct underlay + filtering (Task 1), punch rework + raw-UDP seed (Tasks 6–8), secure untouched except direct removal (Task 9), OpenStream/acceptLoop simplification (Task 10), keepalive 3s/15s (Global Constraints + Task 8 deleting the tight config), stats/doctor (Task 11), faults (Task 12), phases P1/P2/P3 map to Tasks 1–5 / 6–9 / 10–13, test plan (Tasks 1–13), security (Tasks 1, 6), wire format (Global Constraints), decisions capsTightKeepalive/underlayIdle/spike (Task 5, Task 8, Task 4). No spec section lacks a task.

**Step scan:** Every code step names a file, a signature, and the spec value. Test steps name the test and its assertions. No "handle edge cases" placeholders. Deliberately omitted: method bodies for the fan-in and the seed loop (the signatures and the spike/test model determine them).

**Type consistency:** `directUnderlay`/`newDirectUnderlay`/`readFrom`/`writeTo`/`close`/`name`, `setDirectUnderlay`/`clearDirectUnderlay`/`preferredDirect`/`pathName`/`pumpDirect`/`pumpRelay`/`readRelay`/`onDirectIdle`, `registerDirectUnderlay`/`directUnderlayDead`, `markUp(sock, peerAddr, token)`, `seedHandshakeUDPToken`, `newDirectUnderlayToken`, `seedProbeMagic`, `seedTokenLen`, `directUnderlayIdle` are used consistently across tasks.

**Review Focus:** Each of the five lines has an owning-task test: (1) Task 1 `TestDirectUnderlayFiltersForeignSource`, (2) Task 1 `TestDirectUnderlayEchoesSeedMagic` + Task 7 `TestRegisterDirectUnderlayRetiresOldSocket`, (3) Task 2 `TestPairReadFromFanInReturnsDummyAddr` + Task 4, (4) Task 4 `TestPairCloseReturnsEOF`, (5) Task 7 `TestRegisterDirectUnderlayRetiresOldSocket`.

**Proportion:** Plan is longer than the spec but each task carries only the decisions an implementer cannot make alone; bodies are left to the implementer except where the algorithm is not determined.

---

## Plan Revision (2026-10-06)

The 2026-10-06 spec review (spec §「复审修订」) added lifecycle/reliability requirements. **Where this section differs from a task above, this section wins.**

### Task 0: Decouple the pair lifecycle from the relay (H1, P0 — do first)

**Files:** Modify `p2p/internal/host/engine.go`; Test `p2p/internal/host/engine_test.go`, `p2p/internal/host/relaykcp_test.go`.

**Why:** `resetsPairKCP` (`engine.go:2160-2166`) is true for `reasonLinkLost / reasonPeerGone / reasonPeerGoneProbe / reasonPeerRekeyed / reasonSecureDesync / reasonEngineClosed`; relay loss runs `dropRelayKCP` → `pair.shutdown()` (`:2242`/`:1131`) and `closeRelayKCPs` → every pair shutdown (`:1759`/`:1149`). With one unified pair that kills the direct underlay on relay churn. The relay-secure delete (`:1747`) and the `dropSecure` path (`:2231-2233`) carry the same coupling.

**Produces:**
- `func (e *engine) pairHasLiveDirect(peer derpclient.PublicKey) bool` — the peer's pair holds an installed direct underlay with `time.Since(lastRecv) < directUnderlayIdle` (share the predicate with Task 3's `preferredDirect`).
- At each reset decision site, reset the pair / delete the relay secure **only when `!pairHasLiveDirect(peer)`**; `closeRelayKCPs` skips pairs with a live direct underlay (their relay underlay is merely unregistered; the pair keeps running).
- Internals of `secureSessionLocked` / `dropRelaySecure` / `resetPeerSession` and the secure wire protocol stay unchanged.

- [ ] Step 1: characterize with tests — (a) direct live + relay link-lost ⇒ pair, secure object identity, nonce counters, and open streams all survive; (b) no direct ⇒ reset exactly as today (pin against the existing relay-loss tests).
- [ ] Step 2: run `-race`; assert no goroutine/session leak.
- [ ] Step 3: implement the conditional guard.
- [ ] Step 4: relay/secure/engine suites green.
- [ ] Step 5: commit `fix(p2p): keep the pair alive across relay loss when direct is live`.

### Task 14: Per-path KCP congestion setting (after Task 4, H5)

**Files:** Modify `p2p/internal/host/relaykcp.go`; Test `p2p/internal/host/relaykcp_test.go`.
On each `preferred()` flip call `sess.SetNoDelay(1, 10, 2, nc)` with `nc=0` on direct and `nc=1` on relay. `SetMtu(1400)` / `SetWindowSize(256,256)` unchanged (window is per-session). Test: preferred direct ⇒ last `SetNoDelay` arg 0; relay ⇒ 1.

### Task 1 (H2): echo seed magic, never drop

Edited into Task 1 above: `readFrom` echoes `seedProbeMagic` packets back to `u.peer` and continues (late seed responder), so a peer whose own echo was lost still finishes its seed. `TestDirectUnderlayEchoesSeedMagic` asserts the echo is received and the packet is not returned to KCP.

### Task 4 + Task 7 (H4): watchdog callback must not self-join

`pumpDirect` invoking `onDirectIdle` must not block on a clear that joins that same pump. Run the callback in its own goroutine, or make `clearDirectUnderlay` signal-only (no join) and have `pumpDirect` select on the per-underlay stop channel. Add a leak/deadlock guard to `TestPairDirectIdleFiresCallbackOnce`.

### Task 7 + Task 8 (H3): no warm standby; back off short-lived direct

Document in code that "direct registered but relay-preferred" has no stable state (preferred and the watchdog share one threshold). In `directUnderlayDead`, apply exponential backoff keyed on the direct underlay's lifetime: a direct that dies within `2 × directUnderlayIdle` of registration doubles the next punch backoff (capped). Add a test that a repeatedly-short-lived direct backs off instead of flapping.

### Task 10 (M3): first-connection behavior

Test expectation change: opening a stream before any punch succeeds returns `transport == "derp"` (it no longer blocks on `punchAndWait`); migration happens later once the underlay is registered.

### Task 11 (M1): transport label semantics

`transport` / Status now means "pair's current path", not a stream's lifelong plane. Update any consumer/test that assumed it was stable.

### Task 12 (M2): per-path mute

In addition to muting all data at `pair.WriteTo`, support muting only the direct underlay so a test can prove "direct dies, relay recovers".

### Global deltas

- Pair is alive if **any** underlay is alive (Task 0).
- `directUnderlayIdle` is also the "live direct" predicate (Task 0 + Task 3).
- Spike file retained (Task 5).
- Task ordering: **0 → 1 → 2 → 3 → 4 → 14 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13**.
