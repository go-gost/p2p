# p2p relay 面静默死亡检测与加速重建 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** relay 面的静默死亡即时上报并立即重建，砍掉 ~18s 的"没人发现"延迟；relay 路径真断时两击升级到 pair 重置。

**Architecture:** 复用已存在的 `acceptLoop` 退出做死亡信号（零新 goroutine，上报前先 `Close()` 修好 `IsClosed()` 不变量，pair 活性门控重建）；每 pair 一个自带 ticker 的 watchdog goroutine 做 relay 静默的两击升级（第一击只杀 mux，第二击杀 pair）；churn 接续是前置修复。

**Tech Stack:** Go, smux v1.5.57 (`Session.CloseChan` 不用，用 `AcceptStream` 错误返回），kcp-go v5.6.72（只读，不碰 readLoop），slog 结构化日志。

**Spec:** `p2p/docs/superpowers/specs/2026-10-08-p2p-peer-liveness-design.md` — the plan argues from the spec, so the spec travels with it; executors read both.

## Global Constraints

- p2p 是独立 git 仓（`/root/code/go-gost/p2p`）；在 feature 分支 `p2p-peer-liveness` 上就地工作；commit ≠ push，**绝不 push**。
- 所有 go 命令加 `GOWORK=off`；`-race` 必须再加 `CGO_ENABLED=1`。
- 门禁：`GOWORK=off go build ./...` 与 `CGO_ENABLED=1 GOWORK=off go test -race -p 1 -count=1 ./...` 全绿；`internal/host` 单包全量约 225s，禁止无 `-p 1` 的通配测试。
- TDD：每个 Task 先写红测试再实现；每 Task 一 commit。
- `sessionEndReason` 保持封闭集；只允许新增 `relay-silent` 一个值，不动 `resetsPairKCP` / `relayChurnReason` 分支。
- 只动 relay 面；不新增 Status 字段 / RPC；tick 永不进 KCP 读路径。

## Review Focus

- 死亡回调与并发 kill 的竞态：kill 落在"已检查 `pc.closed`"与"`ensureSession`"之间时，不得重建已 kill 的 adapter（`ensureSession` 在 closed 上返回 `errPeerSessionClosed`，行为靠它兜底，测试钉住）→ Task 2 的 `TestDeathReportRacingKillStandsDown`。
- watchdog 在 pair 尚未建 session 时触发（endpoint 为 nil）：不得 kill 一个从未 build 的 adapter（以 `sessAt` 非零为守卫）→ Task 3 的 `TestRelayWatchdogIgnoresSessionlessPair`。
- 被 drop 的 pair 的 watchdog goroutine 不得泄漏：随 `p.done` 退出 → Task 3 的 `TestRelayWatchdogExitsWithPair`。
- 死亡回调调 `ensureSession` 不得阻塞上报 goroutine：用 `(false, false)` 非等待版，测试加超时守卫 → Task 2 的 handler 测试统一 `go test -timeout 60s` 约束。
- 同一死亡被上报两次（acceptLoop 退出 + keepalive 兜底 Close 都被看到）：第二次看到活会话或已换代会话时静默返回，零重复重建 → Task 2 的 `TestDuplicateDeathReportIsIdempotent`。

## File Structure

- `p2p/internal/host/engine.go` — Task 1 接续三字段；Task 2 新增 `relayLiveWindow` + `peerRelaySessionEnded`；Task 3 新增 `reasonRelaySilent` + `relayPathSilent`；Task 4 同步封闭集注释。
- `p2p/internal/host/direct.go` — Task 2 只动 `acceptLoop` 的 `"derp"` 错误分支（一处 `return` 变上报）。
- `p2p/internal/host/relaykcp.go` — Task 3 新增 `relayIdleWindow` / `relayIdleTick` + `watchRelayIdle` + `reportRelayIdle` + pair 级 strike/latch 状态。
- `p2p/internal/host/session_death_test.go`（新建，Task 2）、`p2p/internal/host/relay_watchdog_test.go`（新建，Task 3）；Task 1 的测试追加进 `session_observability_test.go`。
- `p2p/docs/2026-10-08-p2p-peer-down-reading-the-logs.md`、`p2p/doctor/doctor.go` + `doctor_test.go` — Task 4。

---

### Task 1: churn 状态跨 adapter 接续（前置）

**Files:**
- Modify: `p2p/internal/host/engine.go`（`peerConn` 换 adapter 处，与 `storm.carryTo` 相邻行）
- Test: `p2p/internal/host/session_observability_test.go`（追加）

**Interfaces:**
- Consumes: 既有接续块（`sessAt` / `relayRebuilds` / `relayRebuildPeers` / `lastEndReason` / `storm.carryTo`）。
- Produces: 换 adapter 后 `churn` / `churnFrom` / `churnTripped` 与旧 adapter 一致（Task 3 的 strike 接续依赖同一语义；无新函数）。

- [ ] **Step 1: 写红测试 `TestChurnSurvivesAdapterSwap`**
  两次 kill 同一 peer（中间走一次 adapter 换代），断言第二次 kill 后该 peer 的 churn 计数为 2（当前行为：换代清零，计数为 1，测试为红）。
- [ ] **Step 2: 跑红**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -run 'TestChurnSurvivesAdapterSwap' -count=1 ./internal/host/`
  Expected: FAIL（计数为 1）。
- [ ] **Step 3: 在接续块加三行**：`pc.churn / pc.churnFrom / pc.churnTripped = dead.churn / dead.churnFrom / dead.churnTripped`，位置紧贴 `dead.storm.carryTo(&pc.storm)`，注释写明与 storm 同类（pair 级状态）。
- [ ] **Step 4: 跑绿（含包内回归）**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -count=1 ./internal/host/`
  Expected: PASS。
- [ ] **Step 5: Commit**
  `git add internal/host/engine.go internal/host/session_observability_test.go && git commit -m "fix(p2p): carry churn window across adapter swaps"`

---
### Task 2: `acceptLoop` 退出即死亡信号（零新 goroutine）

**Files:**
- Modify: `p2p/internal/host/direct.go`（`acceptLoop` 的 `"derp"` 错误分支）、`p2p/internal/host/engine.go`（新增 `relayLiveWindow` var 默认 6s + `peerRelaySessionEnded`）
- Test: `p2p/internal/host/session_death_test.go`（新建）

**Interfaces:**
- Consumes: `e.peerConn(peer)` 查找 adapter（`onDirectInbound` 先例）；`e.relayKCPFreshness(peer)` 读 pair 活性（killSession 之前必须在 `pc.mu` 之外读，锁序同 killSession）；`pc.ensureSession(false, false)` 非等待重建；`pc.liveSessionLocked()`。
- Produces: `func (e *engine) peerRelaySessionEnded(sess *smux.Session, peer derpclient.PublicKey, err error)`（Task 3 不依赖它，独立事件源）；Debug 行 `peer relay session ended`（字段 `peer` / `error` / `deduped` / `pairFresh`）。

- [ ] **Step 1: 写红测试（4 个，同一文件）**
  - `TestSessionEndReportedWithoutKill`：构造 §2.3 窗口（underlay 读错后 `IsClosed()==false` 的会话），调 handler，断言 `IsClosed()` 变 true、`ended` 行存在、`pc.closed` 仍 false。
  - `TestDeathHandlerDedupsAgainstKill`：先 `killSession` 再调 handler，断言零 `ensureSession` 调用（以重建计数器不断言，或以 `pc.sess` 指针不变断言）。
  - `TestDeathHandlerRebuildsOnFreshPair`：pair 新鲜（`lastRelayRecv` 为 now）时死亡，断言重建发生、重建行带 `downFor` 且 `relayReason` 为空。
  - `TestDeathHandlerStandsDownOnStalePair`：pair 陈旧（`lastRelayRecv` 回拨超 `relayLiveWindow`）时死亡，断言零重建、只有 `ended` 行。
  - `TestDeathReportRacingKillStandsDown`（Review Focus 1）：handler 与并发 `killSession` 竞态，断言 adapter 被 kill 后无重建、无 panic。
  - `TestDuplicateDeathReportIsIdempotent`（Review Focus 5）：同一死亡上报两次，断言只重建一次。
- [ ] **Step 2: 跑红**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -run 'TestSessionEndReportedWithoutKill|TestDeathHandler|TestDeathReport|TestDuplicateDeathReport' -count=1 ./internal/host/`
  Expected: FAIL（`peerRelaySessionEnded` 未定义，编译失败即红）。
- [ ] **Step 3: 实现 `peerRelaySessionEnded`（`engine.go`，紧贴 `onDirectInbound`）**
  顺序即契约：① `relayKCPFreshness`（`pc.mu` 之外）；② `peerConn(peer)`，nil 则返；③ `pc.mu` 下三检查——`pc.sess != sess` 则返（已换代，Review Focus 5）、`pc.closed` 则返（kill 路径拥有，记 `deduped=true` 日志后返）；④ `sess.IsClosed()` 为 false 则 `sess.Close()`（修 §2.3 不变量）；⑤ pair 新鲜（freshness 在 `relayLiveWindow` 内）则 `ensureSession(false, false)`（B 路径即时触发），陈旧则只发 `ended` 行。`ensureSession` 返回 `errPeerSessionClosed` 视为竞态成功（Review Focus 1），记 Debug 不报错。
- [ ] **Step 4: 接 `acceptLoop`（`direct.go` 仅 `"derp"` 分支）**
  `return // session dead` 改为派发 `go e.peerRelaySessionEnded(sess, peer, err)` 后 return（`reportDirectInbound` 先例：回调自带 goroutine，不占数据路径）。direct 分支、`peerAddr` 参数原样不动。
- [ ] **Step 5: 跑绿（含包内回归）**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -count=1 -timeout 600s ./internal/host/`
  Expected: PASS。
- [ ] **Step 6: Commit**
  `git add internal/host/direct.go internal/host/engine.go internal/host/session_death_test.go && git commit -m "feat(p2p): report relay session death on acceptLoop exit"`

---

### Task 3: relay idle watchdog 与两击升级

**Files:**
- Modify: `p2p/internal/host/relaykcp.go`（`relayIdleWindow` / `relayIdleTick` vars、`watchRelayIdle`、`reportRelayIdle`、pair 级 `relayIdleFired` + `relayStrikes`）、`p2p/internal/host/engine.go`（`reasonRelaySilent`、`relayPathSilent`）
- Test: `p2p/internal/host/relay_watchdog_test.go`（新建）

**Interfaces:**
- Consumes: Task 2 的 `killSession`（签名不变）；`newRelayKCPPair` 的 `go p.pumpRelay()` 相邻行（watchdog 同处启动）；`readRelay` 的 `lastRelayRecv` 盖戳处（episode 关闭挂同一锁内）；`p.done`（退出信号，与 pump 同契约）。
- Produces: `func (p *relayKCPPair) reportRelayIdle() (strike int, silentFor time.Duration)`（strike 0=本 episode 已触发过，无动作；1/≥2=行动）；`func (e *engine) relayPathSilent(peer derpclient.PublicKey, strike int, silentFor time.Duration)`；Debug 行 `relay path silent`（字段 `peer` / `silentFor` relay 实测值 / `strike`）；`reasonRelaySilent = "relay-silent"`。

- [ ] **Step 1: 写红测试（5 个，同一文件；`relayIdleWindow`/`relayIdleTick` 按 `directUnderlayIdle=150ms` 先例在测试内改小并 defer 还原）**
  - `TestRelayWatchdogFirstStrikeKillsMuxOnly`：relay 静默超窗，第一击 kill 行 reason 为 `relay-silent`，且 pair 仍在（`relayKCPPairGet` 非 nil）、key 复用。
  - `TestRelayWatchdogSecondStrikeResetsPair`：episode 延续（重建后仍无 relay 入站），第二击 kill 行 reason 为 `link-lost`，且 pair 被删。
  - `TestRelayWatchdogRearmsOnTraffic`：episode 内来一个 relay 数据报，strike 清零、无 kill。
  - `TestRelayWatchdogIgnoresSessionlessPair`（Review Focus 2）：从未 build（`sessAt` 零值）的 pair 静默超窗，零 kill。
  - `TestRelayWatchdogExitsWithPair`（Review Focus 3）：`dropRelayKCP` 后 watchdog goroutine 退出（以既有 pump 退出断言模式为准）。
- [ ] **Step 2: 跑红**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -run 'TestRelayWatchdog' -count=1 ./internal/host/`
  Expected: FAIL（`reportRelayIdle` 未定义，编译失败即红）。
- [ ] **Step 3: 实现 pair 侧（`relaykcp.go`）**
  `relayKCPPair` 加 `relayIdleFired bool` + `relayStrikes int`；`readRelay` 成功返回处（`lastRelayRecv` 盖戳同一锁内）清零两者；`reportRelayIdle() (int, time.Duration)`：`lastRelayRecv` 未超 `relayIdleWindow` 返回 `(0, 0)`；超了且 `relayIdleFired` 返回 `(0, 0)`（latch，同 `pumpDirect` 的 `idleFired`）；否则置 latch、`relayStrikes++`（cap 到 2），返回 `(strikes, now-lastRelayRecv)`。`watchRelayIdle()`：ticker 取 `relayIdleTick`（var 默认 1s，测试可改），每 tick 调 `reportRelayIdle`，strike>0 则 `go e.relayPathSilent(peer, strike, silentFor)`（engine 侧决策，不占 tick），select `p.done` 退出。`newRelayKCPPair` 内紧贴 `go p.pumpRelay()` 加 `go p.watchRelayIdle()`。**tick 永不进 `ReadFrom`/读路径**（kcp-go readLoop 遇错永久退出，见 spec §4.3）。
- [ ] **Step 4: 实现 engine 侧（`engine.go`，紧贴 `directUnderlayDead`）**
  `reasonRelaySilent` 进 `sessionEndReason` const 块（注释：watchdog 第一击，clean death，pair 存活）；另在 `errPeerSessionClosed` 相邻处加 `var errRelaySilent = errors.New("derp engine: relay path silent")`，作为两次 strike 的 cause（与其它 kill 的 cause 同级，只用于日志与 `dropRelayKCP` 的 cause 透传）；`relayPathSilent`：先发 `relay path silent` 证据行（`silentFor` 用 pair 实测的 relay 值），strike==1 → `killSession(errRelaySilent, false, reasonRelaySilent)`，strike≥2 → `killSession(errRelaySilent, false, reasonLinkLost)`（`link-lost` 已在 `resetsPairKCP` 内，H1 抑制与 churn 计数自动生效，不加分支）。
- [ ] **Step 5: 跑绿（含包内回归）**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -count=1 -timeout 600s ./internal/host/`
  Expected: PASS。
- [ ] **Step 6: Commit**
  `git add internal/host/relaykcp.go internal/host/engine.go internal/host/relay_watchdog_test.go && git commit -m "feat(p2p): relay idle watchdog with two-strike escalation"`

---
### Task 4: 读法——文档与 doctor（只加注释与建议，不加数据）

**Files:**
- Modify: `p2p/docs/2026-10-08-p2p-peer-down-reading-the-logs.md`、`p2p/doctor/doctor.go`、`p2p/doctor_test.go`、`p2p/internal/host/engine.go`（`sessionEndReason` 封闭集注释同步 `relay-silent`）
- Test: `p2p/doctor_test.go`（追加 substring 断言，`TestReportStatesThePeerDownPairingRule` 先例）

**Interfaces:**
- Consumes: Task 2 的行名 `peer relay session ended`（字段 `peer`/`error`/`deduped`/`pairFresh`）与 Task 3 的行名 `relay path silent`（字段 `peer`/`silentFor`/`strike`）及 reason 值 `relay-silent`——原样引用，不得改名。
- Produces: 无新代码接口；交付 ops 文档新一节 + doctor 建议行。

- [ ] **Step 1: 写红测试**
  `doctor_test.go` 追加 `TestReportMentionsRelaySilentStrikes`：report 文本含 `relay-silent` 且含 strike 2 即 pair 重置的解释句。当前为红（doctor 无此句）。
- [ ] **Step 2: 跑红**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -run 'TestReportMentionsRelaySilentStrikes' -count=1 ./doctor/`
  Expected: FAIL。
- [ ] **Step 3: 写文档与 doctor 行**
  ops 文档加一节"两击序列读法"：`strike=1`+`relay-silent` kill、`strike=2`+`link-lost` kill+`relay kcp pair reset` 的先后顺序；并写明 `relay path silent` 行的 `silentFor` 是 relay 面实测、kill 行的 `silentFor` 是 `freshestRecv` 合并值，两者含义不同。doctor 加一条建议行（peer 出现 strike 2 即"relay 路径真断过一次"）。`sessionEndReason` 块注释同步 `relay-silent` 的含义（一句话）。
- [ ] **Step 4: 跑绿**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go test -count=1 ./doctor/`
  Expected: PASS。
- [ ] **Step 5: 全仓门禁（四个 Task 的最终 gate）**
  Run: `cd /root/code/go-gost/p2p && GOWORK=off go build ./... && CGO_ENABLED=1 GOWORK=off go test -race -p 1 -count=1 ./...`
  Expected: 全 11 包 PASS（`internal/host` 约 225s）。
- [ ] **Step 6: Commit**
  `git add docs/2026-10-08-p2p-peer-down-reading-the-logs.md doctor/doctor.go doctor/doctor_test.go internal/host/engine.go && git commit -m "docs(p2p): reading guide and doctor advice for relay-silent strikes"`
