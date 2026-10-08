# p2p peer 断链成对可观测性设计

日期：2026-10-08 | 状态：**v1 已交付**（日志字段 + 读法落地），v2 待消费方 | 路径：**bounded**（全部落在 p2p 一个仓；doctor 报告由 p2p 自己的 `doctor` 包渲染，wisper 零改动）

> 本文按实现结果回写。行号一律用**符号**引用：本次改动给 `engine.go` 加了约 110 行，原先按行号写的坐标已全部失效，符号不会。

## 1. 目标

让hub 侧对 peer 断链的观测从「靠人翻日志考古」变成「一行之内可读」。

要解决的具体问题：2026-10-07 息屏断链调查时，判断「链路是否自愈、断了多久」只能手工对齐 hub 日志里 8 条 `relay session rebuilt sessionAge=15.00-15.02s gen=N` 的时间线，而且**第一次读错了**——把它当成例行回收，因此得出「没有断链」的错误结论。那 8 次重建实际是 smux 15 秒超时判死后的真实重建（`sessionAge` 精确等于 `smuxKeepAliveTimeout`）。缺的不是数据，是配对与语义。

## 2. 交付切片

| | 内容 | 状态 |
|---|---|---|
| **v1** | `relay session rebuilt` 补 `relayReason`/`downFor`/`silentFor`；读法规则落到运维文档 + doctor 脚注 + 两处发射点注释 | **已交付**（本仓分支 `p2p-peer-down-events`） |
| **v2** | `Status`/`PeerDiagnostic` 的 `LastRebuildAge`/`SessionDownTotal`/`SessionDownMax`；doctor 每个 peer 一行 | **推迟**：没有具名消费方；doctor 是粘贴快照不是告警源；`Status` 过 gRPC 而 proto 里连 `RelayRebuilds` 都没有，新增字段对 CLI 不可见（见 §5.2）。若只补一个字段，补 `LastRebuildAge` |

## 3. 对原设计的修正（实现前查证）

| # | 原设计说 | 实际 | 处理 |
|---|---|---|---|
| 1 | 「跨 p2p + wisper 两仓，doctor 页在 wisper」 | `doctor` 包**在 p2p 内**：`doctor/doctor.go` `func Report(st p2p.Status, opts Options) string`；wisper 的 `api/p2p_handler.go` 只是消费者 | 全改动在 p2p 一个仓，wisper 零改动；路径由 architectural 降为 bounded |
| 2 | 「新增 `relayKCPSnapshot.lastRecvAt`」 | 字段已存在：`relayKCPPair.lastRelayRecv`/`lastDirectRecv`，`snapshot()` 已填充 | 不加字段；recency 改走新出口 `relayKCPPair.freshestRecv()`（§4.1） |
| 3 | `Status` 加 `SessionRebuilds` | `PeerDiagnostic.RelayRebuilds` 已存在且已渲染（doctor 的 `relay churn` 行），缺的只是 Status 侧汇总 | 不新增重复字段 |
| 4 | `downFor` 来源 =「kill 时间戳」 | **smux keepalive 超时（§4 认定的唯一死亡出口）不走 `killSession`**。`sessionLocked` 注释写明自死的 session 经 `peerConn` 重建而非 `ensureSession`；`killSession` 置 `pc.closed=true` 而 `ensureSession` 见 closed 即返回 —— **两条路径互斥：A ⇔ 有 kill，B ⇔ 无 kill** | 字段改为 **`deadSince`**，在**死亡被观察到**的那一刻打点：A=`killSession`，B=`ensureSession` 的 `replaced` 分支 |
| 5 | `silentFor` 由 `relayKCPSnapshotAttrs` 在**发射时**算出 | 两个问题：① 发射时点漂移——打日志时 peer 可能已恢复发送，span 塌成 ≈0；② 被 `present` 门吞掉——9 个 kill reason 里 6 个走 `resetsPairKCP`，`killSession → dropRelayKCP → delete(e.relayKCPs, peer)`，重建时 `relayKCPPairGet` 返回 nil → attrs 全 nil，而这正是 `link-lost`/`secure-desync`/`peer-rekeyed` 这类最该看的场景 | 在**观察时**取值（pair 的 relay/direct 合并recency），存进 `pc`，发射时只读存量 |
| 6 | 死亡侧只有 `peer session killed` 可配对 | relay 面 accept loop 对 session 死亡**不打日志**（只在 `transport=="direct"` 时打）。静默判死这条主路径上只有一个信号 | §5 按新事实重写，并落到使用者可见处 |
| 7 | —— | `Status` 过 gRPC（`grpc/rpc.go` → `plugin/p2p/proto/p2p.proto`），而那个 message 连 `RelayRebuilds` 都没有 | 沿用既有先例：新行同样 in-process only，§5.2 写明 |

## 4. 方案

### 4.1 日志：补字段，不新增行（v1 已交付）

`relay session rebuilt` 自足——一行之内读出「为什么重建、断了多久、静默多久」，无需跨行算术。两条重建路径都补，缺一条就覆盖不到主场景。

| attr | 含义 | 来源 |
|---|---|---|
| `relayReason` | 被替换的 session 为什么结束；**空串 = 静默判死** | A：`dead.lastEndReason`（原本已读出，未进 attrs）；B：`pc.lastEndReason`，实际上恒为空 |
| `downFor` | 观察到死亡 → 打出这行日志的时长 | 新增 `peerConn.deadSince`（观察时打点） |
| `silentFor` | pair 最后一个 underlay 数据报 → 观察到死亡的时长 | 新增 `peerConn.silentFor`，观察时从 `relayKCPPair.freshestRecv()` 取 |

**两个阶段，不能混**：观察阶段在死亡被看到的那一刻把起点和静默量抓下来存进 `peerConn`；发射阶段只读存量，不再现场测。

- 观察点只有两处，与发射点一一对应：A 在 `killSession`（释放 `pc.mu` 后取 freshness、再取 `pc.mu` 打点，**必须在 `dropRelayKCP` 之前**，否则 pair 已删）；B 在 `ensureSession` 的 `replaced` 分支，且**仅当 `deadSince` 为零时**打点（同一次死亡不重复打点）。
- 消费在发射点**同一个 `pc.mu` 块**里读出并清零：清零写在锁外会与 `killSession` 的写入竞争（`-race` 会报），不清零则下一次重建会把上一次死亡的时长算进来。A 处消费后**不**复制给新 pc——那一行就是这次死亡的记录。
- 两个发射点共用 `relayDownAttrs(reason, deadSince, silentFor, now)`，「哪些字段出现」的规则只写一遍、只测一遍。
- 未观测到死亡时只出 `relayReason`，不出两个时长：零值时间会被渲染成「自公元 1 年起算」的荒谬时长（`killSession` 对 `sessionAge` 已有同款防护）。

**为什么必须去 pair 取 `silentFor`**：断链起点只在 pair 级（`lastRelayRecv`/`lastDirectRecv`），而 `killSession` 是 peerConn 级，跨了一层。且必须取**合并值**：peer 迁到 direct 之后 `pc.lastFrameAt`（relay 专属）就陈旧了，relay 侧会读成「静默很久」，而 peer 其实一直在直连发。

**为什么不拆 `relayKCPSnapshotAttrs` 的 `present` 门**：那条门的既有理由是「零值不能读成健康的空闲会话」，对 KCP stats 是对的；recency 是另一个问题，另开出口即可。

**`downFor` 不含重建握手**：日志先打、session 后建，所以它回答的是「断了多久」，不是「恢复用了多久」。

### 4.2 计数（v2，推迟）

**断链次数不新增字段**：`PeerDiagnostic.RelayRebuilds` 已存在且 doctor 已渲染，缺的只是 `Status` 侧聚合。真正要新增的是 `LastRebuildAge`、`SessionDownTotal`、`SessionDownMax`；`SessionDownMax` 优先于平均值——卡死是长尾问题，平均值会把它稀释掉。

**新行与 `relay churn` 同样 in-process only，`p2p doctor` CLI 看不到**：`Status` 过 gRPC（`grpc/rpc.go` → `plugin/p2p/proto/p2p.proto`），而那个 message 连 `RelayRebuilds` 都没映射。验收时不要因为 CLI 看不到就判成「功能没生效」。

### 4.3 doctor（v1 落地的是读法，不是数据）

v1 在 `verdicts:` 段末尾加一条**脚注**（`doctorDownPairingRule`），内容就是 §5 的规则——它不是判定，是读法：报告里没有任何数字能显示一次 down 或 up，而没有这条规则，后来者会把「rebuild 无 kill」当丢失事件去「修」。

peer 块上的三个数（次数/最近/累计/最长）属 v2，沿用既有**条件渲染**约定（健康 peer 不出该行，见 `TestReportRelayChurn`）。所以「缺失即信号」只约束**日志**，不约束 doctor。

## 5. 关键语义

### 5.1 判定规则（已按事实重写）

> **一次断链 = 一条 `relay session rebuilt`。**
>
> - `relayReason` **空串** = smux keepalive 静默判死，没有任何 kill；非空 = 本端主动 kill。
> - **有 kill 必有 rebuild**：kill 会关掉 adapter，重建只能经 `peerConn` 换一个。所以「有 `peer session killed`、找不到配对的 rebuild」= **这次断链没有自愈**。
> - **rebuild 无 kill 是常态，不是 bug。** 静默判死在 relay 侧一个字都不打，主路径上唯一的信号就是 rebuild 那一行。

原设计把规则锚在 kill 线上（§3 第 6 条），与主路径相反。规则已落到三处使用者可见的位置：`docs/2026-10-08-p2p-peer-down-reading-the-logs.md`、`doctor` 的verdicts 脚注、两处发射点的代码注释。

### 5.2 读法

- `silentFor` ≈ 0 → 死亡突发/主动，看 `relayReason`；
- `silentFor` 明显 > 0 → peer 先静默才被判死，链路问题的形状（黑洞、WiFi 切 4G、relay 断）；
- `silentFor=0` 是「说不出」而不是「没静默」：pair 从没建过、pair 已被**更早**的一次事件删掉（六个 reason 会 `delete(e.relayKCPs, peer)`），或者 peer 真的刚说过话。读 recency 的时机刻意选在本次 `dropRelayKCP` **之前**，所以**本次**死亡不会抹掉自己的测量值。

## 6. 测试（v1 已落地）

- `TestRelayKCPPairFreshestRecv`：合并 recency 的五个形状，外加「pair 无 KCP session 但 recency 仍在时照样返回」——这条是 `downFor` 能成立的前提。
- `TestEngineRelayKCPFreshness`：无 pair 时报 false，而不是一个会被下游算成「自 1970 年」的零值。
- `TestSessionRebuildLogCarriesReasonAndDownDurations`：A/B 两路径分开断言。A 用 `peerConn → killSession → peerConn`，**不能**套 `TestSessionRebuildLogReportsReuseAndStreak` 的骨架（那是 B，且链上没有 kill，`relayReason` 必为空）；B 断言 `relayReason` 是**存在且为空**。
- `TestRelayDownAttrsWithoutAnObservedDeath`：零值规则直接测共享helper，不伪造「已 closed 但未打点」的 adapter——`pc.closed = true` 全仓只在 `killSession` 出现，未观测到的死亡在生产里不可达。
- `TestResendIntervalSafeToChangeWhileEnginesAreLive`（顺带修的既有缺陷，见 §8）：`resendInterval` 是包级 var，两个测试会改，而**更早的测试留下的引擎 goroutine** 可能正在 `ensureSession` 的重试循环里读它。这是数据竞争，`-race` 会让**整个包**变红（它第一次出现时红在 `TestRelayHandshakeLostReplyHeals` 的第一行上）。改为 `*atomic.Int64` 纳秒。
- 回归门禁：`GOWORK=off go build ./...`、`CGO_ENABLED=1 go test -race -p 1 ./...`（`-p 1` 必须，见 §9）。

## 7. 验收

门禁：`go build ./...` + 全量 `-race -p 1`（结果见分支提交记录）。

形状验收（两种都要跑，缺一即覆盖不全）：

- **静默判死**（息屏场景，主路径）：全程**没有** `peer session killed`，只有一条 `relay session rebuilt`，`relayReason` 空、`downFor`/`silentFor` 都有值，量级接近 `smuxKeepAliveTimeout`（15s）。
- **主动 kill**（`link-lost`/`secure-desync` 等）：kill 行与 rebuild 行按 `gen` 配对；此形状下 `kcpConv`/`kcpBytes*` **会缺失**（pair 已删）——**这是预期，不是回归**，别顺手「修」。

## 8. 非目标

- 不改任何判定逻辑：smux 仍是唯一死亡出口，3s/15s 阈值不动。
- 不拆 `relayKCPSnapshotAttrs` 的 `present` 门。
- 不扩 gRPC proto。
- wisper 零改动。
- 不做告警/阈值触发。
- 不解决「为何卡死」：hub 侧永远分不清「Doze 冻住」与「进程死亡」，对它都只是「没有帧」。
- **这是本 incident 的最后一次字段扩张**：之后 peer-down 类信号走 `verdicts` 机制，不再往 `Status` 上加。（`Status`/`peerBlock` 已经是第 N 次可观测性增量，累积成本在维护面。）

## 9. 待决策项

**是否为 peer 补一条周期 liveness 日志？** 倾向**加**。理由不止是多一个信号：§5.1 的配对规则是**缺失性**推理，依赖「有 kill 必有 rebuild」这个**没有任何测试锁住的代码不变式**——一旦有人改了 kill 路径，规则静默失效且无人察觉。一条**存在性**信号（周期 liveness，每 60s 一行，带 `pc.lastFrameAt` 年龄）比缺失性推理结实得多。原非目标给的理由（心跳会重新制造 2026-10-07 的误读）**不成立**：那次误读的成因不是心跳太多，而是日志里没有 peer 粒度的 liveness——hub↔derp keepalive 照打和 peer→hub 静默是两个信号，混在一起才产生了「例行回收」的误读。

若决定不加，则必须补一条测试把「有 kill 必有 rebuild」锁住，否则 §5.1 的规则没有地基。

## 10. 自查

- 无 TBD/TODO；三条设计选择（观察时取值、只补字段、两条路径都补）均有代码与测试为证。
- 与既有事实无矛盾：两条重建路径（`peerConn` 的 `dead != nil` 分支、`ensureSession` 的 `replaced` 分支）都带新字段，且两条路径互斥。
- 并发纪律：新字段由 `pc.mu` 保护，读+清零在同一块；未引入新的锁序边（`relayKCPFreshness` 在释放 `pc.mu` 后调用）。