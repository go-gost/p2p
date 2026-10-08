# 实现计划：p2p peer 断链成对可观测性

日期：2026-10-08 | spec：`docs/superpowers/specs/2026-10-08-p2p-peer-down-events-design.md` | 路径：**bounded**

## 0. 对 spec 的三处修正（实现前已查证）

| # | spec 说 | 实际 | 处理 |
|---|---|---|---|
| 1 | 「跨 p2p + wisper 两仓，doctor 页在 wisper」 | `doctor` 包**在 p2p 内**：`p2p/doctor/doctor.go:45` `func Report(st p2p.Status, opts Options) string`；wisper `api/p2p_handler.go:113` 只是消费者 | **全改动在 p2p 一个仓**，wisper 零改动。路径由 architectural 降为 bounded |
| 2 | 「新增 `relayKCPSnapshot.lastRecvAt`」 | 字段已存在：`relayLastRecv`/`directLastRecv`（`relaykcp.go:338-339`），`snapshot()` 已填充（`relaykcp.go:466-467`） | **不加字段**，只在 `relayKCPSnapshotAttrs` 里发出来 |
| 3 | `Status` 加 `SessionRebuilds` | `PeerDiagnostic.RelayRebuilds` 已存在且已渲染（`doctor.go:149`），缺的只是 Status 侧汇总 | 不新增重复字段，`Status.RelayRebuilds` 做聚合 |

另修正 spec §6 一句：doctor 的渲染约定是**条件渲染**（健康 peer 不出该行，见 `TestReportRelayChurn` 的 228-230 行断言）。所以「缺失即信号」只适用于**日志**（无配对的 `relay session rebuilt`），doctor 里 peer 块恒渲染、只有断链行条件出现。

## 1. 已确证的实现事实

- smux keepalive `smuxKeepAliveInterval=3s` / `smuxKeepAliveTimeout=15s`（`engine.go:721-722`）是 peer 死亡判定的**唯一**出口（`engine.go:703-720` 注释记录 derper 的 `PeerGone` 不发给 relay 客户端）
- `killSession`（`engine.go:2642`）已打 `peer session killed`，带 `relayReason`/`dropSecure`/`sessionAge`/`cause`/`gen`（`engine.go:2690`）
- `relay session rebuilt` 有**两处**发射点，两处都要补字段：
  - **A** `engine.go:1590-1606`（`ensureSession` 的 adapter 替换路径，`dead != nil` 才走得到）
  - **B** `engine.go:2185-2209`（`ensureSession` 原地重建，`replaced := pc.sess != nil && pc.sess.IsClosed()`）
- B 路径**没有 kill 记录**：`killSession` 会置 `pc.closed = true` 并关 `closeCh`，而 B 只看 `sess.IsClosed()`。所以 B 上 `lastKilledAt` 常为零 → `downFor` 必须零值省略，B 的主要时长信号是 `silentFor`。
- `lastEndReason` 在 A 处已被读出（`engine.go:1560`）但没进 attrs；B 处未读，但 `recordRebuild(pc.lastEndReason)`（`engine.go:2438`）在同一次 `ensureSession` 内、发射之后才消费并清空（`:2439`），所以 B 发射时 `lastEndReason` 仍在。
- pair 级数据已有管道：`relayKCPLogAttrs(peer)`（`engine.go:1308`）→ `relayKCPSnapshotAttrs`（`relaykcp.go:485`），A 处已 `append`（`engine.go:1605`），B 处也已 `append`（`engine.go:2208`）
- 计数器连续性：A 处新 pc 是全新结构体，`relayRebuilds` 等**必须从 dead 复制**（`engine.go:1568-1572` 有注释说明理由）；B 处留在同一 pc 上
- 测试夹具：`logCapture`（`session_lock_test.go:334`），用法 `capture.nth(msg, i) map[string]string`（`:361`）、`capture.count(msg) int`（`:603`）；引擎 `newEngine("", "", priv, slog.New(capture))`（`:393`）
- 已有的 rebuild 日志测试：`TestSessionRebuildLogReportsReuseAndStreak`（`session_lock_test.go:450`）、`relaykcp_stats_test.go:209`
- doctor：`peerBlock`（`doctor.go:139`）、现有 `relay churn` 条件行（`doctor.go:149-152`）、测试 `TestReportRelayChurn`（`doctor_test.go:207`）
- Status 汇总：`internal/host/server.go:347-353`（按 `PeerDiagnostics` 求和，`PeerDiagnostic` 构造在 `engine.go:277-296`）
- 门禁：`GOWORK=off go build ./...`、`CGO_ENABLED=1 go test -race -p 1 ./...`

## 2. 字段契约

**日志（两处发射点一致）**

| attr | 类型 | 来源 | 零值行为 |
|---|---|---|---|
| `relayReason` | string | A: `dead.lastEndReason`；B: `pc.lastEndReason` | 恒发（零值是空串，与 killed 行的既有行为一致） |
| `downFor` | Duration | `now - pc.lastKilledAt`，**发射后清零** | `lastKilledAt` 为零则**不发此 attr**（不得报 1970 年起算） |
| `silentFor` | Duration | pair 的 relay/direct `lastRecv` 中**较新者** → `now` | 两者皆零则不发；pair 无 KCP session 时随 `relayKCPSnapshotAttrs` 的 nil 一起缺 |

`silentFor` 取**较新者**而非只看 relay：直连面存活时 relay 的 `lastRecv` 会正常变旧，只看它会把健康的直连 peer 报成静默。这与 `PeerDiagnostic.LastRecvAge` 取 merged 值的既有语义一致。

`downFor` 与 `silentFor` **不可互换**：`silentFor` ≈ `smuxKeepAliveTimeout`（纯静默），`downFor` 含重建握手（实测基线 ~33s，见 `engine.go:713-716`）。

**doctor 行（条件渲染，同 `relay churn`）**
```
    session down   12s ago, total 1m5s, worst 22s
```
出现条件：`d.LastRebuildAge > 0 || d.SessionDownTotal > 0`。

## 3. 任务清单

### Task 1 — pair 侧发出 `silentFor`

1. **红**：`internal/host/relaykcp_test.go`（或 `relaykcp_stats_test.go`，跟随既有 pair 测试落位）加测试：构造 pair 快照，断言 `relayKCPSnapshotAttrs` 含 `silentFor`；`lastRelayRecv`/`lastDirectRecv` 全为零时该 attr 不出现；仅 relay 新鲜时取 relay、仅 direct 新鲜时取 direct、两者都陈旧时取较新者。
2. **绿**：`relayKCPSnapshot` 加派生字段 `silentFor time.Duration`（**不是**新的 lastRecv 字段——那两个已存在）；`snapshot()`（`relaykcp.go:454`）内计算：取 `lastRelayRecv`/`lastDirectRecv` 的较新者，`now.Sub(fresh)`，皆零则 0；`relayKCPSnapshotAttrs`（`relaykcp.go:485`）在 `present` 分支内加 `"silentFor", s.silentFor.Round(time.Millisecond)`。
3. **提交**：`feat(relaykcp): report the pair's last-seen age in log attrs`

### Task 2 — peerConn 记 `lastKilledAt`，两处 rebuild 日志补三字段

1. **红**：`session_lock_test.go` 加 `TestSessionRebuildLogCarriesReasonAndDownDurations`：
   - A 路径：照 `TestSessionRebuildLogReportsReuseAndStreak` 的骨架造 `dead`（closed sess + `sessAt`），先 `pc.killSession(..., reasonX)` 语义上补上 `dead.lastKilledAt`，再调 `ensureSession`；断言 `relayReason` == reasonX、`downFor` 非空且 ≥ 0、`silentFor` 存在。
   - 零值：`dead` 未经过 kill（`lastKilledAt` 零）时断言 `downFor` **不出现**在 attrs 里。
   - B 路径：照同文件 B 场景断言 `relayReason` 来自 `pc.lastEndReason`；`lastKilledAt` 为零时 `downFor` 缺省但 `silentFor` 仍在。
   - 复用 `logCapture.nth` / `newEngine` / `newTestSess` / `newSecureSession`，**不新造夹具**。
2. **绿**：
   - `peerConn` 加 `lastKilledAt time.Time`（紧邻 `lastEndReason`，`engine.go:531` 附近），注释写明「set by killSession, consumed by the next rebuild log, zero when the session ended without a kill」。
   - `killSession`（`engine.go:2649` 旁）持 `pc.mu` 时 `pc.lastKilledAt = time.Now()`。
   - A 处（`engine.go:1590`）加 `downFor`/`relayReason`，`silentFor` 由既有 `append(rebuildAttrs, e.relayKCPLogAttrs(peer)...)`（`:1605`）带入；**不**把 `lastKilledAt` 复制给新 pc（消费掉）。
   - B 处（`engine.go:2185-2210`）：在既有 `pc.mu.Unlock()` 前的锁块里读 `reason := pc.lastEndReason`、`killedAt := pc.lastKilledAt`（**仅 `replaced` 时**），加进 `replacedAttrs`；发射后清 `pc.lastKilledAt`。
3. **提交**：`feat(host): pair down/up events on the rebuild log`

### Task 3 — `Status` / `PeerDiagnostic` 计数

1. **红**：`internal/host` 加测试：一次 kill+rebuild 后 `PeerDiagnostics[peer].SessionDownTotal` == 记录的 `downFor`、`SessionDownMax` ≥ 它、`LastRebuildAge` 落在 (0, 测试耗时]；`Status` 侧 `RelayRebuilds`/`SessionDownTotal`/`SessionDownMax` 与逐 peer 求和一致（沿用 `server.go:347` 的求和写法断言）。再补一条**单调性**：`SessionDownMax` 只增不减（第二次更短的断链后仍保留旧值）。
2. **绿**：
   - `status.go`：`PeerDiagnostic` 加 `LastRebuildAge`、`SessionDownTotal`、`SessionDownMax`（均 `time.Duration`，注释写清 `0` = 从未重建）；`Status` 加 `RelayRebuilds int64`、`SessionDownTotal`、`SessionDownMax time.Duration`（注释对齐 `PairMigrations` 那段既有措辞，并注明 in-process only，gRPC proto 冻结）。
   - `peerConn` 加 `downTotal time.Duration` / `downMax time.Duration` / `lastRebuildAt time.Time`。
   - A 处从 `dead` 复制 `downTotal`/`downMax`（紧邻 `:1569` 的 `relayRebuilds` 复制），并把本次 `downFor` 累加、置 `pc.lastRebuildAt = now`；B 处直接在 `pc` 上累加并置时间戳。累加只发生在 `downFor` 实际算出时（零值不累加）。
   - `engine.go:277-296` 的 `PeerDiagnostic` 构造填三个字段；`server.go:347-353` 的求和循环加 `st.RelayRebuilds += d.RelayRebuilds`、`st.SessionDownTotal += d.SessionDownTotal`、`st.SessionDownMax` 取 max。
3. **提交**：`feat(host): session-down counters in Status`

### Task 4 — doctor 渲染

1. **红**：`doctor/doctor_test.go` 加 `TestReportSessionDown`：有断链的 peer 出 `session down` 行且含「多久前 / 累计 / 最长」三个数；全零的 peer **不**出该行（沿用 `TestReportRelayChurn` 的 base 闭包写法）。
2. **绿**：`doctor.go` 的 `peerBlock` 在 `relay churn` 行之后加条件行，条件 `d.LastRebuildAge > 0 || d.SessionDownTotal > 0`，值 `fmt.Sprintf("%s ago, total %s, worst %s", d.LastRebuildAge, d.SessionDownTotal, d.SessionDownMax)`，注释引用 spec §5 说明「缺行 = 没断过」。
3. **提交**：`feat(doctor): render session-down history per peer`

### Task 5 — 门禁与验收

1. `GOWORK=off go build ./...`
2. `CGO_ENABLED=1 go test -race -p 1 ./...`
3. **验收（比门禁重要）**：一次真实断链后 `silentFor` ≈ 15s、`downFor` ≈ 33s 量级；并在 hub 日志上跑通 spec §5 的判定规则——`peer session killed` 的每个 `gen=N` 都有配对的 `relay session rebuilt`。
4. 把 spec 的三处修正回写进 spec 文件，`git commit`（docs）。

## 4. 非目标（复核，防漂移）

- 不改任何判定逻辑：smux 仍是唯一死亡出口，3s/15s 阈值不动。
- 不加告警/阈值触发。
- 不为「未重建的静默 peer」补周期心跳日志 —— 那会重新制造 2026-10-07 那次误读（hub 每 ~24s 照打 keepalive，peer 被冻住时毫无区别）。
- wisper 零改动（doctor 在 p2p 内）。
