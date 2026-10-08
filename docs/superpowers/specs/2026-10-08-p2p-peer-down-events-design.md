# p2p peer 断链成对可观测性设计

日期：2026-10-08 | 状态：draft 待 review | 路径：architectural（跨 p2p + wisper 两个仓库）

## 1. 目标

让 hub 侧对 peer 断链的观测从「靠人翻日志考古」变成「一条 grep + doctor 页一眼可见」。

要解决的具体问题：2026-10-07 息屏断链调查时，判断「链路是否自愈、断了多久」只能手工对齐 hub 日志里 8 条 `relay session rebuilt sessionAge=15.00-15.02s gen=N` 的时间线，而且**第一次读错了**——把它当成例行回收，因此得出「没有断链」的错误结论。那 8 次重建实际是 smux 15 秒超时判死后的真实重建（`sessionAge` 精确等于 `smuxKeepAliveTimeout`）。缺的不是数据，是配对与语义。

本设计的产出同时是 **15 分钟息屏验收的判定工具**：验收要回答「解锁后多久恢复」和「有没有哪次卡死不自愈」，今天这两个问题都无法自动判定。

## 2. 已确证的事实（实现依据）

- **peer 死亡判定的唯一机制是 smux keepalive**：`smuxKeepAliveInterval = 3s`、`smuxKeepAliveTimeout = 15s`（`internal/host/engine.go:721-722`），作用于 per-pair relay session。
- **没有替代机制**。`engine.go:703-720` 的注释明确：只有 peer 自己发来的帧喂给 session 的 liveness，而 derper 的 `PeerGone` 是 best-effort（发给 mesh watchers，不发给 open-relay 客户端），所以「远端消失的 session 只能在这里被发现」。
- **`DerpKeepAlive` / `keepAlivePeriod` 与 peer 无关**：它只管 `keepalive(c *derpclient.Client)`，即 hub↔derper 那一腿（`keepAlivePeriod = 30s`，`engine.go:699`）。
- **死亡侧日志已存在且信息完整**：`killSession`（`engine.go:2690`）打 `peer session killed`，带 `relayReason`（类型化 `sessionEndReason`）、`dropSecure`、`sessionAge`、`cause`、`gen`。
- **恢复侧日志已存在**：`relay session rebuilt`（`engine.go:1606`，adapter 替换路径；`engine.go:2209`，原地重建路径），带 `sessionAge`、`gen`、`secureReuse`、`desyncStreak`。
- **两行可靠 `gen` 配对**；`lastEndReason` 在 `engine.go:1560` 已从 `dead` 读出，只是没放进 attrs。
- **pair 级数据已有管道**：`relayKCPLogAttrs`（`engine.go:1308`）→ `relayKCPSnapshotAttrs`（`relaykcp.go:485`）已在 `relay session rebuilt` 里带出 `kcpBytesSent/Rcvd` 等。
- **现成可复用的公共字段**：`PeerDiagnostic.LastRecvAge`、`Status.PeerTransports`，以及 `PairMigrations`/`PairFallbacks`/`SeedFailures`/`RelayLossSuppressedByDirect` 等 pair 级计数器（`status.go`）。

## 3. 非目标

- **不改任何判定逻辑。** smux 仍是唯一死亡出口，阈值不动。理由：判定本身有实测依据（`engine.go:713-716` 记录了 entrypoint 重启场景 ~33s 空窗），本设计只解决观测。
- **不做告警/阈值触发。** 只落日志与指标，不引入新的自动处置。告警需要一套阈值策略，那是独立决定。
- **不解决「为何卡死」。** hub 侧永远分不清「Doze 冻住」与「进程死亡」——对它都只是「没有帧」。原因属于 spoke 内部状态。
- **不动 hub↔derper 那条腿的可观测性。** 它已有 `derp: keepalive` / `relay path dead`（Error 级，含 `pongAge`）。

## 4. 方案

### 4.1 日志：补字段，不新增行

`relay session rebuilt` 补三个 attr，使其**自足**——一行之内可读出「为什么重建、断了多久、静默多久」，无需跨行算术。

| attr | 含义 | 来源 |
|---|---|---|
| `relayReason` | 谁打死了被替换的 session | `dead.lastEndReason`（`engine.go:1560` 已读出） |
| `downFor` | kill → 重建 的时长（含重建握手） | 新增 `pc.lastKilledAt` |
| `silentFor` | 最后一帧 → 判死 的时长 | 新增 `relayKCPSnapshot.lastRecvAt`（源自 `relayLastRecv`，`relaykcp.go:338`） |

`downFor` 与 `silentFor` **语义不同，不可互换**：`silentFor` 只含静默（约等于 `smuxKeepAliveTimeout`），`downFor` 含重建握手（实测基线 ~33s）。混淆两者会得出错误结论。

**为什么必须去 pair 取 `silentFor`**：断链起点只在 pair 级的 `relayLastRecv`，而 `killSession` 是 peerConn 级——跨了一层。走 snapshot 管道（`relayKCPSnapshotAttrs`）是最短路径，不引入跨层调用。

### 4.2 计数：`Status` 新增三个字段

- `SessionRebuilds` —— 断链重建总次数
- `SessionDownTotal` —— 累计断链时长
- `SessionDownMax` —— **最长单次断链**

`SessionDownMax` 优先于平均值：卡死是长尾问题，平均值会把它稀释掉。

`PeerDiagnostic` 新增 `Rebuilds` 与 `LastRebuildAge`，供 doctor 页按 peer 聚合。

### 4.3 doctor 页：每个 peer 一行

显示：当前路径（已有 `Path`）、断链次数、最近一次断链距今多久、累计断链时长、最长单次断链。

消费者是 wisper 的 `doctor.Report(tunnel.P2PHostStatus(), opts)`（`api/p2p_handler.go:113`）。这是本设计唯一跨到 wisper 的部分。

## 5. 关键语义：缺失即信号

**不新增日志行**意味着：一个持续静默但尚未到 15s 超时的 peer **不会出现在日志里**。因此判定卡死的规则是：

> 存在 `peer session killed`（gen=N）却没有配对的 `relay session rebuilt`（gen=N+1）→ 该 peer 断链后未自愈。

这条规则必须写进 p2p 的代码注释与 doctor 页说明，否则后来者会把它当 bug 去「修」。这是本设计最重要的语义约束。

配套：**不要给未重建的静默 peer 补「周期心跳日志」**。那会重新制造 2026-10-07 今晚的误读——hub 侧每 24s 照打 keepalive，peer 被冻住时也照打，日志里看不出任何区别。

## 6. 测试

- p2p（`internal/host`）：断链-重建配对测试——构造一次 `killSession` 后重建，断言 `relay session rebuilt` 的 `relayReason` 等于 kill 的 reason、`downFor` 非负且 ≥ `silentFor`、`silentFor` 落在 `smuxKeepAliveTimeout` 量级。日志 attrs 的断言可沿用文件内既有的 log-capture 手法（先读现有测试怎么做，不要新发明夹具）。
- p2p：`Status` 新计数器随一次断链递增、`SessionDownMax` 只增不减。
- p2p：`relayKCPSnapshot.lastRecvAt` 在 pair 无 session 时为零值，不得报出「自 1970 年起」。
- wisper（doctor）：报告渲染出三个数字；无断链的 peer 仍渲染该行——**缺失的行会被读成「没有断链」**，因此不可用「有断链才渲染」的条件渲染。
- 回归：`go test ./... -p 1`（`-p 1` 是必须的，见下）；`-race` 需 `CGO_ENABLED=1`。

## 7. 交付门禁

- p2p：`GOWORK=off go build ./...`；`CGO_ENABLED=1 go test -race -p 1 ./...`
- wisper：`GOWORK=off go build ./...`；`go test ./doctor/ ./api/ -count=1`
- 验收（比门禁更重要）：用一次真实断链验证 `downFor`/`silentFor` 的量级合理，且 §5 的判定规则能在 hub 日志上跑通一次。

## 8. 待确认项

无。范围已由用户确认：日志补字段（不新增行）、加计数指标、doctor 页一起改。

## 9. 自查

- 无 TBD/TODO；三条设计选择（snapshot 取值、只补字段、显示次数+最近+最长）均由用户确认。
- 与既有事实无矛盾：`relay session rebuilt` 两条路径（`engine.go:1606` adapter 替换、`engine.go:2209` 原地）都要带新字段，否则原地重建缺 `silentFor`。
- 范围单一：一个 p2p 文件加一个 pair 字段、一个公共 Status 结构扩展、一处 wisper doctor 渲染。不需拆分。
- 歧义已收敛：`downFor`/`silentFor` 差异、缺失即信号、无心跳日志三点均已显式定义。