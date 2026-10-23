# p2p：v6 优先的并发换族打洞 + IPv6 opt-in 开关

> Status: **design**（2026-10-23）。取代 `docs/2026-09-20-p2p-ipv6-direct.md`
> 的「决策 3：同轮内换族重试」的**顺序**形态；其族选择规则、候选编码、
> 「v6 不依赖控制在候选列表上」等其余决策不变。

## Context（为什么做）

2026-09-20 的 v6 设计把换族定为**顺序**：一轮内先 v6（双方都通告 v6 时），
seed 失败再试 v4。当时的论证是「两侧同时判败 → 同时退到 v4 → 收敛」。
2026-10-22/23 的实测推翻了这个前提：

- **两侧 v6 都坏时会相位锁定**。每侧的轮次是 `[v6 seed][v4 seed][backoff]`，
  seed 是阻塞的（上限 `seedTimeout`，生产 5s）。两侧的轮次起点一旦错开半个
  seed，就变成「A 在 v4 窗口时 B 还在 v6」——两侧的 v4 窗口**永远不重叠**，
  于是 v4 也永远不成功，pair 只能一直走 relay。这不是延迟问题，是可用性
  问题。`TestDirectV6FallbackToV4` 复现的就是它（两侧都通告不可达 v6）。
- **单侧 v6 坏时每轮白付一个 seedTimeout**：v4 明明通，也要先排在坏掉的 v6
  后面等满 5s。首次建链和每次重打洞都要付。
- **seed 不受 punch 自己的预算约束**：`punchTimeout` 的 `ctx` 只包住
  `waitCandidates`（direct.go:1341-1348），seed 用独立的 `seedTimeout` 且串行
  两个族 ⇒ 一轮最长可以是 `punchTimeout + 2×seedTimeout`。
- **v6 现在自动生效**：只要启动时探测到全局 v6 出口就收 v6 候选、发
  `capsIPv6`，没有开关。用户要求改成**默认关闭、显式开启**。

## 目标 / 非目标

**目标**

1. 一个坏掉（或慢）的 v6 **不再挡住**能通的 v4：两个族的 seed 同时起飞。
2. 两侧的 family 窗口**同时开始、时长相同**，相位锁定结构性消失。
3. **v6 严格优先**：v4 先握手成功也不立即采用，等 v6 的结论；v6 能用就一定用 v6。
4. v6 走 **opt-in**（`Config.IPv6`，默认 false）：不开就不探测、不收集、不上报。

**非目标**

- 不改 seed 握手的线上格式（`seedOutcome`、magic、token 都不变）。
- 不引入「每 peer 的族记忆/学习」（如上一轮 v6 失败则下一轮 v4 优先）——
  它在单侧坏的情况下会让两侧选择不一致，2026-09-20 文档已否决，这里不翻案。
- 不引入第二条并发的直连路径：每轮仍然只注册**一个** underlay。

**反目标**（即使技术上成立也算失败）

- 让启用 v6 的用户**更不容易**连上 v6（例如更短的 v6 预算把它挤掉）。
- 在 v4-only 或 v6-off 的部署上改变任何线上行为（除了不再自动发 v6 候选）。

## 约束

- `seedHandshakeUDPToken(sock, peer, timeout)` 不变：一个 socket、一个 token、
  每 `seedRetransmit`(200ms) 重发、回显对端探测、学到源地址。并发只发生在
  **调用层**：每族一个 socket、一次调用。
- `kcp` 的「一个 socket 一个 session」约束要求赢家的 socket 原样交给
  `markUp`；输家的 socket 必须彻底关闭。
- `punch()` 持有 `dc.mu` 的窗口必须短（`notePeerEndpoint`/`noteRound` 的注释
  已说明在锁内调用它们会死锁）。

## 已定的决策（对话中定的，不再讨论）

1. **v6 严格优先**：宁可多等一个 `seedTimeout`，也不要「先到先得」。
2. **并发而不是顺序**（方案 A：两个 socket、两个 goroutine）。
3. **IPv6 opt-in，默认关闭**：`Config.IPv6 bool`。

## 设计

### 一、并发换族

新增一个内部结果类型与一个 helper，`punch()` 的族循环从「顺序 for」变成
「同时起飞 + 按优先级裁决」：

```go
type familyAttempt struct {
    idx  int              // fams 下标
    dial netip.AddrPort   // 本族拨的端点（日志/trace 用）
    out  seedOutcome
    err  error
}
```

- 对 `order`（v6 在前、v4 在后，规则不变）里的**每个**族：
  - 起一个 goroutine 跑 `seedHandshakeUDPToken(f.sock, dial, budget)`；
  - `budget = min(seedTimeout, punch ctx 的剩余预算)`——见下面的「预算」。
- 裁决（严格优先）：
  1. 若 v6 在 `order` 里：**先等 v6 的结果**（成功或失败）。
     - 成功 ⇒ 立即采用 v6：关掉 v4 的 socket 以取消它，**等 v4 的 goroutine
       退出**，然后走原来的成功路径（`noteSeed("ok","v6")`、`notePeerEndpoint`、
       `dc.mine = 赢家候选`、`markUp(赢家 socket, out.Answer, out.Token)`、日志）。
     - 失败 ⇒ 记 `noteSeedFailure("v6", ...)`、`noteSeed("timeout","v6")`，然后
       取 v4 的结果：它要么已经在通道里（并行跑完），要么还在跑（等它）。
  2. 若 v6 不在 `order` 里（只有 v4）：直接等 v4。
  3. 两族都失败 ⇒ 走现有的整轮失败路径（`closeFams()` + `dc.backoff()`）。
- **最坏墙钟时间**从 `2×seedTimeout` 降到 `1×seedTimeout`（两个 seed 并行），
  且两族**都**被尝试过 ⇒ 相位锁定不再可能。
- **报告**按「这次尝试实际发生了什么」记，不按「谁赢了」记：
  | 尝试的结局 | `noteSeed` | `noteSeedFailure` | trace | 失败计数 |
  |---|---|---|---|---|
  | 赢家成功 | `ok` | 否 | `<族> up` | 否 |
  | 对方的 attempt 已完成且成功，但被丢弃 | `ok` | 否 | 无（赢家那条已说明） | 否 |
  | 已完成且失败 | `timeout` | 是（写 `lastErr`） | `<族> seed failed: …` | **是** |
  | 被取消（赢家已定，socket 被关） | **不记** | **否** | `<族> cancelled (v6 up)` | **否** |

  关键点：**取消不是失败**。`noteSeed(result != "ok")` 会直接加到
  `seedFailures`（relaykcp.go:1564-1566），所以被取消的 v4 绝不能调它，否则
  每一次健康的 v6 轮都会往「seed 失败」指标里加一。
  `lastErr` 的顺序天然安全：失败族先写、赢家 `markUp` 会清空
  （direct.go:830），所以「v6 失败 + v4 成功」最终显示 `lastErr = ""`，
  而 trace 保留两条事实。

### 二、预算：本轮不动 `punchTimeout` 的含义

并发本身已经把一轮的最坏墙钟从 `waitCandidates + 2×seedTimeout` 降到
`waitCandidates + seedTimeout`，这就够解掉目标里的两个问题。

曾考虑顺便把 `punchTimeout` 的 `ctx`（direct.go:1341，只喂
`waitCandidates`）扩成整轮上限（`budget = min(seedTimeout, ctx 剩余)`），
**否决**：`ctx` 是在候选收集（STUN 最长 3s）之后才开始的，且已被
`waitCandidates` 与 `candidateGrace` 消耗；用它封顶 seed 会让**对端候选来得
晚的 v4-only 轮**拿到被截断的 seed 预算——这违反「v4-only 部署行为不变」的
反目标。要做得对，得把 `ctx` 提到 `punch()` 入口并穿过候选收集，属于另一件事，
本次不做。

⇒ `punchTimeout` 保持「候选等待的预算」，seed 保持每族 `seedTimeout`。

### 三、IPv6 opt-in

`p2p.Config` 加一个字段：

```go
// IPv6 enables the IPv6 direct-path family: the egress probe, the v6
// candidate collection, and the v6 capability bit. Off by default, so a
// host never advertises or dials v6 unless its operator asked for it.
IPv6 bool `yaml:"ipv6,omitempty"`
```

引擎侧加 `e.v6Enabled bool`（来自 `Config.IPv6`），**门控点**：

| 位置 | 现状 | 改后 |
|---|---|---|
| `Host.Connect` 启动探测（host.go:109-113） | `v6Available = v6Egress() != nil` | 仅当 `v6Enabled` 才探测 |
| **每轮**探测（direct.go:1289-1292） | 只在启动时探到过才重探 | **`v6Enabled` 时每轮重探**（见下） |
| `collectV6`（direct.go:1293-1298） | 有 v6 源就收 | 需本轮的探测结果 |
| `sendCaps(capsIPv6)`（direct.go:1330） | 无条件发 | 仅当**本轮有可用 v6 出口** |
| `directEnabled()`（direct.go:325-330） | v6 有源就算有候选 | v6 项需 `v6Enabled` |
| `DirectConfig.IPv6`（status.go:211） | 「找到/配置了可用 v6」 | **语义不变**（现在可用）；新增 `IPv6Enabled`（配置） |
| doctor 的 `direct config`（doctor.go:99） | `ipv6=%v` | `ipv6=off` / `on (no egress)` / `on` |
| `TestMain`/v6 测试注入 | 设 `e.v6Addr` 即生效 | 还要 `e.v6Enabled = true`（显式） |

**`v6Enabled` 是「常驻许可」，不是「启动时的一次性开关」**：开启后**每一轮**
都重新 `v6Egress()`（一次 `DialUDP` 路由查询，不发包，微秒级）。这样
`v6Available` 退化成**只用于状态**的事实（上一次探测的结果），而不是门控。

这同时修掉一个现有的 bug：`direct.go:1289-1292` 只在启动探测成功过时才重探，
而 `host.go:109-110` 的注释却声称「每轮重探，换出口不用重启」——启动时没有
v6（DAD 未完成、接口/DHCPv6 晚到、笔电换到 v6 网络）的 host 永远用不上 v6。


**关于 `capsIPv6`**：2026-09-20 文档把它定义为「我**理解**该能力」，不是「我
当前提供 v6」，且**没有任何代码按它门控**（族选择只看候选列表）。按用户要求
（「只有开启才上报 ipv6」）本次把它收窄为「**现在能用 v6**」：只在
`v6Enabled` 且本轮确实探到全局 v6 出口时才发。理由：关闭能力的 host 声称
「理解 v6」只会让对端排障时把 `peer caps: ipv6` 读成「它支持 v6」。这是对该
文档语义的**收窄**，记录在此。

**行为变化（预期）**：现在有全局 v6 出口的部署会自动用 v6 直连；升级后**必须**
显式配置 `ipv6: true`，否则退回 v4-only。嵌进 wisper 的那层要能透传这个字段
（wisper 自己有 config，属于本次之外的跟进项）。

### 四、族选择规则（不变，供参照）

- 族顺序：`has6` 且 `has4` ⇒ 先 v6；否则只有可用的那一族。
- v6 拨 `peerV6[0]`；v4 拨 `peerV4[len-1]`，并保留 hairpin 规则（我方公网地址
  == 对端公网地址时改拨 `peerV4[0]`）。
- 这些都在 `punch()` 里、按 `fams` 下标完成，与并发化无关。

## 任务分解（每步独立可验证）

1. **纯重构，不改行为**：把「顺序 for」抽成 `runFamilyAttempts` 的骨架（先
   保持顺序调用，测试全绿）——为并发化留出可 diff 的最小面。
2. **并发化 + 严格优先裁决**：两个 goroutine、结果通道、v6 优先、取消与
   「等 goroutine 退出再动 socket」。加决策表单测（v6 ok / v6 fail+v4 ok /
   两族都 fail / 只有 v4 / v6 成功时 v4 被取消）。
3. **IPv6 开关**：`Config.IPv6` + `e.v6Enabled` + 上表全部门控点；把每轮探测
   从「启动探到过才重探」改成「开启就每轮重探」，`v6Available` 降为状态；
   `v6Addr` 测试注入点改为「显式开启」。
4. **可观测性**：`DirectConfig.IPv6`（可用）保持不变，新增 `IPv6Enabled`；
   doctor 区分 off / on-no-egress / on；`directReason` 在 v6-off 且无 STUN 时
   仍给 `no-candidates`。
5. **文档**：更新 `docs/2026-09-20-p2p-ipv6-direct.md` 的决策 3（指向本文），
   wisper 侧的字段透传另记。

## 测试策略

- **决策表单测**：用一个「只回探测包、永不回显我们 token」的 socket 当坏族
  （现有 `direct_probeoutcome_test.go` 已有这个工具），断言：
  - v6 坏 + v4 好 ⇒ 一轮内 v4 up，且 trace 里 v6 是 timeout、v4 是 up；
  - v6 好 + v4 好 ⇒ v6 up（**严格优先**），v4 的握手被取消；
  - 两族都坏 ⇒ 整轮失败 + backoff；
  - 只有 v4 ⇒ 只尝试 v4；只有 v6 ⇒ 只尝试 v6。
- **回归**：`TestDirectV6FallbackToV4` 的收敛预算可以从 30s 收回（并发后应
  一轮收敛），并可加断言「attempts 只增加 1 轮」。
- **开关**：`IPv6=false` 时**完全不探测**（启动与每轮都不探，`v6Available`
  恒 false）、`sendCaps` 不含 v6 位、候选里无 v6；`IPv6=true` 时行为与今天一致
  （外加「每轮重探」的修复）。
- **-race**：并发 seed 是新并发面，必须在 `-race` 下跑整包（CI 已做）。
- **e2e**：`ipv6-direct` 场景需要 `ipv6: true` 才能跑（当前 e2e 依赖自动探测）。

## 验证

- 本地整包 3 次 + `-race` 1 次全绿（当前基线：修完 flaky 后已 4/4 绿）。
- CI `build-p2p` 的 test job（含 `-race`）通过。
- 手工：无 v6 的机器（本 pod / pi）上 `ipv6` 不配 ⇒ doctor 显示 `ipv6=off`、
  不再出现 v6 候选；配 `ipv6: true` 且无出口 ⇒ `on (no egress)`。
  注意：**这条要经由进程内 API 验证**（wisper 的 `GET /api/p2p/doctor`，它拿的是
  完整 `Status`）；`cmd/p2p doctor` 走 gRPC，`statusFromReply` 不填
  `DirectConfig`（proto 在独立仓库且已冻结），CLI 里看不到这一行——这是已知
  限制，不在本次范围。

## 风险 / 已接受的取舍

- **v6 坏时仍要等一个 seedTimeout**（严格优先的代价，用户已接受）。相对顺序法
  的收益是「等一次而不是两次」，并让 v4 的窗口与 v6 同时开始。
- **并发引入新的 goroutine 生命周期**：必须「先取消/关 socket、再等 goroutine
  退出、最后才动 `fams[i].sock`」，否则会出现「关掉赢家 socket」或双写。
- **默认关闭会静默关掉现有 v6 直连**：这是用户要求的行为变化，必须在发布说明
  里写清楚（否则「升级后 v6 直连没了」会被当成 bug）。
- 输家的 socket 在赢家已定时被强制关闭 ⇒ 它的 goroutine 以一个 socket 错误
  结束；按上面的报告表，这类取消**不**记失败、不进 `seedFailures`。
- **两侧裁决不一致（A 的 v6 成功、B 的 v6 失败）**：只在**时间窗**上可能，不会
  稳定存在——seed 要求 own→peer→own 的完整往返，A 成功意味着 A 的探测被 B 回显，
  而同一个 B 的 socket 也会回显 B 自己的探测（A 的握手无条件回显）。所以
  「B→A 永久不通而 A→B 通」在 seed 层面无法让 A 成功；能发生的只是 B 在 A 的
  探测到达前就结束了本轮。这种时间窗分裂由 underlay 的 idle 看门狗（~6s）退役
  单边路径 + 重新打洞自愈，而并发化把两侧窗口对齐后窗口本身也缩小了。
  ⇒ **接受这个风险**，不在本次引入跨端确认/挂起（那需要新的协议状态，超出非目标）。

## 不做（YAGNI）

- 每 peer 的族记忆 / 上一轮失败的族降级。
- 单 socket 双栈（方案 B）：赢家 socket 变成 v4-mapped，会波及 underlay 的
  对端地址、源过滤与候选通告。
- 把 v6 探测做成独立周期任务：开启后**每轮**探测已经够便宜（一次 `DialUDP`
  路由查询）。
