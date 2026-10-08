# 实现计划：p2p peer 断链成对可观测性

日期：2026-10-08 | spec：`docs/superpowers/specs/2026-10-08-p2p-peer-down-events-design.md` | 路径：**bounded**

交付切片：**v1 = Task 1 + 2 + 2b**（日志侧闭环，独立可交付）；**v2 = Task 3 + 4**（`Status` 计数器与 doctor 行，**需先指定消费方**）。v1 做完不等于 v2 开工 —— 见 §3.0。

## 0. 对 spec 的三处修正（实现前已查证）

| # | spec 说 | 实际 | 处理 |
|---|---|---|---|
| 1 | 「跨 p2p + wisper 两仓，doctor 页在 wisper」 | `doctor` 包**在 p2p 内**：`p2p/doctor/doctor.go:45` `func Report(st p2p.Status, opts Options) string`；wisper `api/p2p_handler.go:113` 只是消费者 | **全改动在 p2p 一个仓**，wisper 零改动。路径由 architectural 降为 bounded |
| 2 | 「新增 `relayKCPSnapshot.lastRecvAt`」 | 字段已存在：`relayLastRecv`/`directLastRecv`（`relaykcp.go:338-339`），`snapshot()` 已填充（`relaykcp.go:466-467`） | **不加字段**；recency 改走新出口，见 §0.1 第 5 条 |
| 3 | `Status` 加 `SessionRebuilds` | `PeerDiagnostic.RelayRebuilds` 已存在且已渲染（`doctor.go:149`），缺的只是 Status 侧汇总 | 不新增重复字段，`Status.RelayRebuilds` 做聚合 |

另修正 spec §6 一句：doctor 的渲染约定是**条件渲染**（健康 peer 不出该行，见 `TestReportRelayChurn` 的 228-230 行断言）。所以「缺失即信号」只适用于**日志**（无配对的 `relay session rebuilt`），doctor 里 peer 块恒渲染、只有断链行条件出现。

### 0.1 review 后的修正（阻塞项）

第一版把「断链时长」挂在 `pc.lastKilledAt` 上。实现前查证发现这条路径**覆盖不到本设计要诊断的那个事件**，已改为「在死亡被观察到的那一刻打点」，两处发射点共用。

| # | 原计划 | 实际 | 处理 |
|---|---|---|---|
| 4 | `downFor` 来源 = `pc.lastKilledAt`，只有 kill 路径有值 | **smux keepalive 超时（spec §2 认定的唯一死亡出口）不走 `killSession`**。`sessionLocked` 的注释写明「died on its own — any kill closes the adapter too (killSession), so a killed session rebuilds through peerConn, not here」（`engine.go:2361-2368`），`TestRelaySessionReplaceDeadSessionKeepsKeys` 的文档同样写明「the smux keepalive timeout starved it and nothing killed the adapter… does not pass through pc.kill」（`session_lock_test.go:260-266`）。且 `killSession` 置 `pc.closed=true`（`engine.go:2648`）而 `ensureSession` 见 closed 即返回（`:2167-2170`）——**两条路径互斥：A ⇔ 有 kill，B ⇔ 无 kill** | 字段改为 **`deadSince`**，在死亡被观察处打点：A 路径 `killSession`、B 路径 `ensureSession` 的 `replaced` 分支（`engine.go:2183`）。`downFor` 在两条路径上都有值 |
| 5 | `silentFor` 由 `relayKCPSnapshotAttrs` 在**发射时**算出 | 两个问题：① **发射时点漂移** —— 打日志时 peer 可能已经恢复发送，`lastRecv` 是新的，`silentFor` 读出 ≈0，把 15s 黑洞报成 0s；只有外发触发的重建（`engine.go:854` OpenStream → `peerConn`）没有包在途，才偶然正确。② **被 `present` 门吞掉** —— 9 个 kill reason 里有 6 个走 `resetsPairKCP`（`engine.go:2544-2550`），`killSession` 调 `dropRelayKCP`（`:2687`）而它 `delete(e.relayKCPs, peer)`（`:1395`），重建时 `relayKCPPairGet` 返回 nil（`:1159-1163`）→ attrs 全 nil → `silentFor`、`kcpConv`、`kcpBytes*` 一起消失，而这正是 `link-lost`/`secure-desync`/`peer-rekeyed` 这类最该看的场景 | 取值仍走 pair 的 relay/direct **合并**（`pc.lastFrameAt` 只覆盖 relay 面，`engine.go:495-497`，直连迁移后会陈旧，不能替代），但改为在**观察时**取值并存到 pc；A 路径在 `dropRelayKCP` **之前**取 |
| 6 | 死亡侧只有 `peer session killed` 可配对 | relay 面的 accept loop 对 session 死亡**不打日志**（`direct.go:1713-1721` 只在 `transport=="direct"` 时打）。静默判死这条主路径上，从头到尾只有 `relay session rebuilt` 一个信号 | §5 的判定规则按新事实重写，并落到使用者可见的位置（Task 2b） |
| 7 | —— | `Status` 过 gRPC（`grpc/rpc.go:50-81` → `plugin/p2p/proto/p2p.proto:67-85`），而那个 message 连 `RelayRebuilds` 都没有 —— `relay churn` 行今天就已经只对进程内调用方可见 | 沿用既有先例：新行同样 in-process only，在 spec §4.2 写明「CLI 看不到」，避免验收时误判功能没生效 |

## 1. 已确证的实现事实

- smux keepalive `smuxKeepAliveInterval=3s` / `smuxKeepAliveTimeout=15s`（`engine.go:721-722`）是 peer 死亡判定的**唯一**出口（`engine.go:703-720` 注释记录 derper 的 `PeerGone` 不发给 relay 客户端）
- `killSession`（`engine.go:2642`）已打 `peer session killed`，带 `relayReason`/`dropSecure`/`sessionAge`/`cause`/`gen`（`engine.go:2690`）
- `relay session rebuilt` 有**两处**发射点，两处都要补字段：
  - **A** `engine.go:1590-1606`（在 **`e.peerConn`** 里，`dead != nil` 才走得到 —— 别去 `ensureSession` 找）
  - **B** `engine.go:2185-2209`（`ensureSession` 原地重建，`replaced := pc.sess != nil && pc.sess.IsClosed()`）
- B 路径**没有 kill 记录**：`killSession` 会置 `pc.closed = true` 并关 `closeCh`，而 B 只看 `sess.IsClosed()`。所以 B 上不存在任何 kill 时间戳 —— 这不是「常为零」，而是**结构性为零**（见 §0.1 第 4 条），因此断链起点必须另打点。
- **两条路径互斥**（`sessionLocked` 注释，`engine.go:2361-2368`）：A ⇔ 走过 `killSession`；B ⇔ session 自己死掉（smux keepalive 超时）。任何新字段都必须同时覆盖两边，否则覆盖不到主场景。
- `lastEndReason` 在 A 处已被读出（`engine.go:1560`）但没进 attrs；B 处未读，但 `recordRebuild(pc.lastEndReason)`（`engine.go:2438`）在同一次 `ensureSession` 内、发射之后才消费并清空（`:2439`），所以 B 发射时 `lastEndReason` 仍在。
- B 上的 `lastEndReason` **实际上恒为空**：任何 `killSession` 都会同时置 `closed`，而 closed 的 adapter 进不了 B；A 复制过来的 reason 被替换 adapter 的首次 build 消费掉（该 build 一定带 rebuild 标记，见 `engine.go:1564-1567`）。所以 B 的 `relayReason` 只是「空串 = 静默判死」的显式声明，测试不要写成对非空值的断言。
- pair 级数据已有管道：`relayKCPLogAttrs(peer)`（`engine.go:1308`）→ `relayKCPSnapshotAttrs`（`relaykcp.go:485`），A 处已 `append`（`engine.go:1605`），B 处也已 `append`（`engine.go:2208`）
- 计数器连续性：A 处新 pc 是全新结构体，`relayRebuilds` 等**必须从 dead 复制**（`engine.go:1568-1572` 有注释说明理由）；B 处留在同一 pc 上
- 测试夹具：`logCapture`（`session_lock_test.go:334`），用法 `capture.nth(msg, i) map[string]string`（`:361`）、`capture.count(msg) int`（`:603`）；引擎 `newEngine("", "", priv, slog.New(capture))`（`:393`）
- 已有的 rebuild 日志测试：**B 路径**参照 `TestSessionRebuildLogReportsReuseAndStreak`（`session_lock_test.go:450`，手搓 `peerConn` 字面量 + `ensureSession`）、`TestRelaySessionReplaceDeadSessionKeepsKeys`（`:267`）；**A 路径**参照 `relaykcp_stats_test.go:185-228`（`e.peerConn` → `killSession` → 再 `e.peerConn`，然后断言 attrs）与 `session_observability_test.go:157-181`。新测试落 `session_observability_test.go`（该文件就是这批日志/计数断言的家），不要新造夹具。
- doctor：`peerBlock`（`doctor.go:139`）、现有 `relay churn` 条件行（`doctor.go:149-152`）、测试 `TestReportRelayChurn`（`doctor_test.go:207`）
- Status 汇总：`internal/host/server.go:347-353`（按 `PeerDiagnostics` 求和，`PeerDiagnostic` 构造在 `engine.go:277-296`）
- **并发纪律**：`peerConn` 上已有的一批字段是 atomic，理由就写在旁边（`engine.go:495-497`、`502-504`：「An atomic so a status read never takes `pc.mu`」）。`peerDiagnostics` 在 `e.mu` 已释放后构造每个 `PeerDiagnostic`，只读 atomic、不取 `pc.mu`。新增字段沿用 atomic，不要引入新的锁序边。
- `ageOf(now, nano)` 未设置时返回 0（`engine.go:356-362`）——零值语义直接沿用，不要自己再判一次。
- 门禁：`GOWORK=off go build ./...`、`CGO_ENABLED=1 go test -race -p 1 ./...`

## 2. 字段契约

**两个阶段，不能混**：**观察**阶段在「死亡被看到」的那一刻把起点和静默量抓下来存进 `peerConn`；**发射**阶段只读这些存量，不再去现场测。任何在发射时测出来的时长都会漂移（peer 可能已经恢复），任何从 `relayKCPSnapshotAttrs` 拿的值都会被 `present` 门吞掉（§0.1 第 5 条）。

**观察点（唯一的两处，与发射点一一对应）**

| 路径 | 观察点 | 锁序 |
|---|---|---|
| A（有 kill） | `killSession`：`pc.mu.Unlock()`（`engine.go:2662`）之后、`dropRelayKCP`（`:2687`）**之前**取 freshness，再回 `pc.mu` 落盘 | 先 kcpMu 后 pc.mu，**绝不持 `pc.mu` 取 kcpMu** —— `relayKCPLogAttrs` 的两处调用（`:1605`/`:2208`）都是刻意在锁外的 |
| B（静默判死） | `ensureSession`：`pc.mu.Unlock()`（`:2196`）之后取 freshness，回 `pc.mu` 落盘，**仅当 `replaced` 且 `deadSince` 仍为零**（同一次死亡不重复打点） | 同上 |

**pc 上新增的两个存量字段**：`deadSince time.Time`（断链起点）、`silentFor time.Duration`（死亡瞬间的静默量）。注释写明：`deadSince` 由上述两处观察点置位、由下一次 rebuild 日志**读并清**；零值表示这次死亡没被打点过（例如从未 kill、也无原地重建）。

**日志（两处发射点一致）**

| attr | 类型 | 来源 | 零值行为 |
|---|---|---|---|
| `relayReason` | string | A: `dead.lastEndReason`；B: `pc.lastEndReason` | 恒发（零值是空串，与 killed 行的既有行为一致）。B 上实际恒为空串，见 §1 |
| `downFor` | Duration | 发射时 `now - deadSince`，**读 `deadSince` 与清零在同一个 `pc.mu` 块内完成**（A 从 `dead` 读，不复制给新 pc） | `deadSince` 为零则**不发此 attr**（不得报 1970 年起算） |
| `silentFor` | Duration | 观察点抓下的存量 | 零值则不发；A 路径一定能取到（pair 尚在），B 路径 pair 若从未收过帧则缺 |

**`silentFor` 取 pair 的 relay/direct 合并值**（较新者），与 `PeerDiagnostic.LastRecvAge` 同源同义：直连面存活时 relay 的 `lastRecv` 会正常变旧，只看它会把健康的直连 peer 报成静默；反过来 `pc.lastFrameAt` 只覆盖 relay 面（`engine.go:495-497`），直连迁移后同样不可用。两者都不能单独成立，只能合并。

**`downFor` 与 `silentFor` 不可互换**，且都不是「重建握手耗时」：`silentFor` ≈ `smuxKeepAliveTimeout`（纯静默）；`downFor` 的含义是「死亡被观察到 → 下一次重建被触发」，实测基线 ~33s（`engine.go:713-716`），但这个时长里装的是 **peer 什么时候回来**，不是重建本身花多久 —— 重建日志在 build **之前**就发（`session_lock_test.go:475` 的注释已记录这点）。key 被 drop 时重握手的时间**不在** `downFor` 里。注释按这个口径写，别写成「含重建握手」。

**doctor 行（条件渲染，同 `relay churn`）**
```
    session down   12s ago, total 1m5s, worst 22s
```
出现条件：`d.LastRebuildAge > 0 || d.SessionDownTotal > 0`。

## 3. 任务清单

### 3.0 为什么切两刀

价值高度不均匀，混在一起做会让便宜的必要项被贵的可选项拖住：

- **日志侧（Task 1 + 2 + 2b）** 是唯一直接修掉 2026-10-07 那次误读的部分，也是**唯一一处当前完全不产生输出**的地方（§0.1 第 6 条）。不新增日志行、不碰判定逻辑、独立可交付。
- **`Status` 计数器 + doctor 行（Task 3 + 4）** 有三个减分项：① `Status` 过 gRPC 而 proto 未映射（§0.1 第 7 条），hub 上没有消费者，只有进程内调用方看得到；② doctor 的定位是「贴给维护者的快照」而不是告警源，「累计/最长」在一次性快照里的边际价值明显低于「最近一次断了多久」；③ 计划原本没有写出**谁看这一行、看完做什么决定**。

所以 v2 的开工条件是：**先写下消费方**（wisper 前端横幅？hub 侧趋势？纯人工看粘贴报告？）。写不出来就默认不做，v1 的日志已经能回答 2026-10-07 缺的那个问题。若 v2 确实只想要一个字段，优先留 `LastRebuildAge` —— 累计与最长可以在真需要时再加。

### Task 1 — pair 侧提供「合并 recency」（不带 `present` 门）

1. **红**：`internal/host/relaykcp_test.go`（或 `relaykcp_stats_test.go`，跟随既有 pair 测试落位）加测试：仅 relay 新鲜 → 取 relay；仅 direct 新鲜 → 取 direct；两者都陈旧 → 取较新者；两者皆零 → `ok=false`；**`present=false`（pair 已无 KCP session）但 recency 仍在时，必须照样返回**——这一条是 Task 2 能成立的前提，别漏。
2. **绿**：`relayKCPPair` 加 `freshestRecv() (time.Time, bool)`（持 `p.mu`，取 `lastRelayRecv`/`lastDirectRecv` 的较新者，皆零返回零值 + `false`）；engine 加 `relayKCPFreshness(peer) (time.Time, bool)` 包 `relayKCPPairGet`（`engine.go:1159-1163`），pair 不存在则 `false`。**`relayKCPSnapshot` / `relayKCPSnapshotAttrs` 一行不改** —— `present` 门对 KCP stats 是对的（零值不能读成健康的空闲会话），只把 recency 挪到新出口上。
3. **提交**：`feat(relaykcp): expose the pair's freshest underlay recv`

### Task 2 — peerConn 记 `deadSince`/`silentFor`，两处 rebuild 日志补三字段

1. **红**：在 `session_observability_test.go` 加 `TestSessionRebuildLogCarriesReasonAndDownDurations`，两条路径分开写、参照不同：
   - **A 路径**（照 `relaykcp_stats_test.go:185-228` / `session_observability_test.go:157-181`）：`pc := e.peerConn(peer)` → `pc.killSession(err, true, reasonX)` → `pc = e.peerConn(peer)`；断言 `relayReason` == reasonX、`downFor` 存在且 ≥ 0、`silentFor` 存在。**注意**：不能拿 `TestSessionRebuildLogReportsReuseAndStreak` 的骨架（手搓 `peerConn` 字面量 + `ensureSession`）来测 A —— 那是 B 路径，而且那条链上没有 `killSession`，`relayReason` 必然是空。
   - **B 路径**（照 `TestRelaySessionReplaceDeadSessionKeepsKeys`，`session_lock_test.go:267`）：活 adapter + closed `sess`，`pc.ensureSession(false, false)`；断言 `relayReason` **为空串**（静默判死，见 §1）、`downFor` **存在**（本路径的最大改进点：没有 kill 也要有值）、`silentFor` 存在。
   - **零值**：直接构造一个 `replaced` 但从未被打点的 pc（`deadSince` 零），断言 `downFor` **不出现**在 attrs 里，且不报 1970 年起算。
   - 复用 `logCapture.nth` / `newEngine` / `newTestSess` / `newSecureSession` / `settledSecurePair`，**不新造夹具**。
2. **绿**：
   - `peerConn` 加 `deadSince time.Time` 与 `silentFor time.Duration`（紧邻 `lastEndReason`，`engine.go:531` 附近），注释写明置位点（§2 的表）、消费点（下一次 rebuild 日志，读+清同一锁块）、零值含义。
   - `killSession`：`pc.mu.Unlock()`（`:2662`）之后、`dropRelayKCP`（`:2687`）**之前**取 `fresh, ok := pc.e.relayKCPFreshness(pc.peer)`；再 `pc.mu.Lock()` 置 `deadSince = time.Now()`、`silentFor = now.Sub(fresh)`（`ok` 假则留 0）、解锁。顺序不可调换：取 freshness 必须在 pair 被删之前。
   - `ensureSession` 的 `replaced` 分支：`pc.mu.Unlock()`（`:2196`）之后取 freshness，回 `pc.mu`；**仅当 `replaced && deadSince.IsZero()`** 时置位（同一次死亡不重复打点），随后在**同一个 `pc.mu` 块**里读出 `reason`/`silentFor`/`deadSince` 并把 `deadSince`、`silentFor` 清零，发射只用这些局部变量。**清零必须在锁内** —— 锁外写会与 `killSession` 的写竞争，`-race` 会报。
   - A 处（`engine.go:1590-1606`）：从 `dead` 读同一组量（`reason` 已在 `:1560` 读出，一并带上 `deadSince`/`silentFor` 的读+清），算 `downFor`；**不**把它们复制给新 pc（消费掉）。`append(rebuildAttrs, e.relayKCPLogAttrs(peer)...)`（`:1605`）保持原样。
3. **提交**：`feat(host): pair down/up events on the rebuild log`

### Task 2b — 判定规则落到使用者可见处（v1 内）

1. **绿**：relay 面 accept loop 对 session 死亡**不打日志**（`direct.go:1713-1721` 只在 direct 时打），所以静默判死这条主路径上唯一的信号就是 rebuild 行 —— 这行日志必须自带读法，否则重建规则会被后来者当 bug「修」。规则按新事实重述为：
   - 一次断链 = 一条 `relay session rebuilt`（A/B 两条路径都发）；
   - `relayReason` 空串 = smux keepalive 静默判死；非空 = 主动 kill；
   - **有 kill 必有 rebuild**（kill 会换掉 adapter），因此「`peer session killed` 无配对 rebuild」= 断链后未自愈；
   - 「rebuild 无 kill」是常态，**不是** bug。
2. **落点**：`p2p/docs/` 运维文档（与 2026-10-07 那次调查的记录放一起）+ `doctor.Report` 的 `verdicts:` 段（`doctor.go:109-112`）加一条。**别照抄 spec §5 现在的措辞** —— 它锚在 kill 行上，与主路径相反。
3. **同时**把这条规则写进 `engine.go` 两处发射点旁的注释。
4. **提交**：`docs(p2p): state the peer-down pairing rule for log readers`

### Task 3 — `Status` / `PeerDiagnostic` 计数【v2，需先写消费方】

1. **红**：`internal/host` 加测试：
   - 一次 kill+rebuild（A 路径）后 `PeerDiagnostics[peer].SessionDownTotal` 与记录的 `downFor` 相符、`SessionDownMax` ≥ 它、`LastRebuildAge` 落在 (0, 测试耗时]。**断言要留 1ms 容差或直接比对 `downFor.Round(time.Millisecond)`** —— 日志里的 `downFor` 按既有惯例 `.Round(time.Millisecond)`（对照 `sessionAge`，`engine.go:1594`），而计数器存的是原始 `time.Duration`，写 `==` 必挂。
   - **B 路径也必须累加**：静默判死同样是一次断链，修完 §0.1 后 `downFor` 在 B 上有值，累加不能只发生在 A。
   - **跨 adapter 交换的连续性**（计划 §1 已点出这个风险，红测试却漏了）：两次 kill+rebuild 后 `SessionDownTotal` == 两次之和、`SessionDownMax` 仍保留第一次的较大值。照 `relaykcp_stats_test.go:193-207` 的形状写。
   - **单调性**：`SessionDownMax` 只增不减（第二次更短的断链后仍保留旧值）。
   - `Status` 侧 `RelayRebuilds`/`SessionDownTotal` 求和、`SessionDownMax` 取 max，与逐 peer 一致（沿用 `server.go:347-353` 的求和写法断言）。
2. **绿**：
   - `status.go`：`PeerDiagnostic` 加 `LastRebuildAge`、`SessionDownTotal`、`SessionDownMax`（均 `time.Duration`，注释写清 `0` = 从未重建）；`Status` 加 `RelayRebuilds int64`、`SessionDownTotal`、`SessionDownMax time.Duration`（注释对齐 `PairMigrations` 那段既有措辞）。**注明可见性**：gRPC 的 `PeerDiagnostic` message（`plugin/p2p/proto/p2p.proto:67-85`）连 `RelayRebuilds` 都没映射，所以 `relay churn` 行今天就只对进程内调用方可见 —— 新行同理，不扩 proto。
   - `peerConn` 加 `downTotal atomic.Int64` / `downMax atomic.Int64` / `lastRebuildAt atomic.Int64`（纳秒 UnixNano），理由照抄邻居的注释（`engine.go:495-497`）：Status 读取不取 `pc.mu`。**不要用普通字段** —— `peerDiagnostics` 在 `e.mu` 已释放后构造 `PeerDiagnostic`，普通字段就是一处 `-race`。
   - A 处：从 `dead` 复制 `downTotal`/`downMax`（紧邻 `:1569` 的 `relayRebuilds` 复制，同为 atomic 故无需 `dead.mu`），再把本次 `downFor` 累加、`lastRebuildAt` 置 `now`。B 处直接在 `pc` 上累加并置时间戳。累加只发生在 `downFor` 实际算出时（零值不累加）。
   - `engine.go:277-296` 的 `PeerDiagnostic` 构造填三个字段（时间戳走 `ageOf` 或 `time.Unix(0, nano)`，零值直接透传 0）；`server.go:347-353` 的求和循环加 `st.RelayRebuilds += d.RelayRebuilds`、`st.SessionDownTotal += d.SessionDownTotal`、`st.SessionDownMax` 取 max。
3. **提交**：`feat(host): session-down counters in Status`

### Task 4 — doctor 渲染【v2，需先写消费方】

1. **红**：`doctor/doctor_test.go` 加 `TestReportSessionDown`：有断链的 peer 出 `session down` 行且含「多久前 / 累计 / 最长」三个数；全零的 peer **不**出该行（沿用 `TestReportRelayChurn` 的 base 闭包写法）。**三个数都要非零**：修完 §0.1 后两条路径都有真实 `downFor`，所以要断言 `total`/`worst` 不是 `0s`，否则一个「累加只发生在 A 路径」的回归照样绿。
2. **绿**：`doctor.go` 的 `peerBlock` 在 `relay churn` 行之后加条件行，条件 `d.LastRebuildAge > 0 || d.SessionDownTotal > 0`，值 `fmt.Sprintf("%s ago, total %s, worst %s", d.LastRebuildAge, d.SessionDownTotal, d.SessionDownMax)`，注释引用 spec §5 说明「缺行 = 没断过」。
3. **提交**：`feat(doctor): render session-down history per peer`

### Task 5 — 门禁与验收

1. `GOWORK=off go build ./...`
2. `CGO_ENABLED=1 go test -race -p 1 ./...`
3. **验收（比门禁重要，v1 的完成标准）**：一次真实断链后 `silentFor` ≈ 15s、`downFor` ≈ 33s 量级；并在 hub 日志上按 Task 2b 的规则走一遍。**两种形状都要验**：
   - **静默判死**（息屏场景，主路径）：全程**没有** `peer session killed`，只有一条 `relay session rebuilt`，`relayReason` 空、`downFor`/`silentFor` 都有值；
   - **主动 kill**（如 `link-lost`/`secure-desync`）：kill 行与 rebuild 行按 `gen` 配对，且此形状下 `kcpConv`/`kcpBytes*` 会缺失（pair 已删）——**这是预期，不是回归**，别顺手「修」。
4. 回写 spec：§0 的三处修正 + §0.1 的四条、§5 按 Task 2b 重写、§4.2 补一句「新行与 `relay churn` 同样 in-process only，`p2p doctor` CLI 看不到」。`git commit`（docs）。

## 4. 非目标（复核，防漂移）

- 不改任何判定逻辑：smux 仍是唯一死亡出口，3s/15s 阈值不动。
- 不动 `relayKCPSnapshotAttrs` 的 `present` 门：零值不能读成「健康的空闲会话」是那条门的既有理由，recency 另开出口（Task 1），不顺手把门拆了。
- 不扩 gRPC proto（`RelayRebuilds` 至今未映射，新行沿用同一先例）。
- wisper 零改动（doctor 在 p2p 内）。
- **这是本 incident 的最后一次字段扩张**：之后 peer-down 类信号走 `verdicts` 机制，不再往 `Status` 上加。（`Status`/`peerBlock` 已经是第 N 次可观测性增量，累积成本在维护面，不在单次实现。）

## 5. 待决策项（不阻塞 v1）

**是否为 peer 补一条周期 liveness 日志？** 原非目标写的是「不补，理由是会重新制造 2026-10-07 那次误读」，但**这个理由不成立**，需要重新裁决：

- 那次误读的成因**不是心跳太多，而是日志里没有 peer 粒度的 liveness**。人看到 `sessionAge=15.00-15.02s` 判成「例行回收」，正是因为 `sessionAge` 在 up 行是「已存活多久」、在 rebuild 行却是「上一个 session 活了多久」—— 同一个词两种含义，且没有任何一行说明「我已经 15 秒没收到这个 peer 的任何东西」。
- 一条每 60s 一行、带 `pc.lastFrameAt` 年龄（`engine.go:1682` 已在打点）的 per-peer 行，正好消除这个歧义：hub↔derp keepalive 正常、`last frame 3m ago`，两者一眼分开。peer 被冻住时**恰恰看得出区别**——原论证把「hub keepalive 照打」当成了心跳无用，但 hub keepalive 是 hub→derp 的方向，与 peer→hub 的 `lastFrameAt` 是两个信号。
- 代价：每 peer 每分钟一行（hub 现已有 24s 一条的 Debug 级 keepalive，同量级）。

倾向：**加**。理由不止是多一个信号 —— Task 2b 的配对规则是**缺失性**推理，依赖「有 kill 必有 rebuild」这个**没有任何测试锁住的代码不变式**；一旦有人改了 kill 路径，规则静默失效且无人察觉。一条**存在性**信号（周期 liveness）比缺失性推理结实得多。若决定不加，则必须补一条测试把那个不变式锁住，否则 §5 的规则没有地基。
