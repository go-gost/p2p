# p2p relay 面静默死亡：检测与加速重建设计

## 1. 目标

relay 面的静默死亡（smux keepalive 判死，引擎全不知情）要能**即时上报**并**立即重建**，
砍掉 `silentFor ≈ 15s` 与 `downFor ≈ 33s` 之间的 ~18s 纯"没人发现"延迟。
`relayReason` 为空的静默判死行，应当变成一个可解释、可计数的两击升级序列。

本设计只管 **relay 面**（Q3 决议）。直连面已有 idle watchdog（`onDirectIdle` /
`directUnderlayIdle`）、死亡日志（`acceptLoop` 的 `transport=="direct"` 分支）
与主动重建触发器（`onDirectInbound`），再加一套会双触发竞争。

## 2. 实现前查证（全部读过代码，不是推测）

### 2.1 死亡链：smux 关 underlay，但从不碰 peerConn

- `smux v1.5.57 keepalive()`（每 15s 的 timeout tick）→ `Session.Close()` →
  `s.conn.Close()`，其中 conn 是 `secureSession.conn` 包出的 `cryptoConn`。
- `cryptoConn` **没有覆盖 `Close`**（只有 Write/Read/readRecord/desync 相关方法），
  所以 `Close` 落到被嵌入的 `net.Conn`，即 `pair.newStream()` 给出的 `*relayKCPStream`。
- `relayKCPStream.Close()` 只做三件事：`p.stream = nil`、把 pair 共享 KCP 会话的
  读 deadline 踢到现在（唤醒一个 park 住的读）、等在途读写退休。
  **pair 的 KCP 会话、`pc.closed`、`lastEndReason` 全都不动。**
- 无 `pc.kill` / `killSession`，无 kill 日志，无 key/pair 重置。
- 全仓**零个 `CloseChan`**；死亡只在三处拉取式 `IsClosed()` 检查可见
  （`liveSessionLocked`、`ensureSession` 的 `replaced` 分支、`sessionLocked`）。

### 2.2 NOP 是双向活性，不是单向探针

smux 的 `recvLoop` 在**每读到一个帧头**就置 session 活跃，位置在命令 switch 之前，
`cmdNOP` 分支不回包但**对端收得到**。两端各 3s 发一次 NOP，互保对方活跃。
因此：relay 面超过 ~6s（两个 ping 周期）无入站数据报，**就是链路真故障，
不是空闲**—— 这是 watchdog 阈值的合法性基础。

bucket 只在数据帧（PSH）分支按载荷扣 token，控制帧不碰；初始值为
`MaxReceiveBuffer`。静默链路上 bucket 恒为正，keepalive 的 CAS 失败守卫
必然关掉会话—— 兜底成立。

### 2.3 `IsClosed()` 在读错误窗口说谎

`recvLoop` 在 underlay 读错误时调 `notifyReadError` 然后 return——
**它不关 `die`**。`Close()` 是唯一置 `closed` 的地方。
于是有窗口：会话已死、`acceptLoop` 已返回，但 `IsClosed()` 仍 false，
`ensureSession` 照常返回这具尸体；`openStream` 的 SYN 排队无人收 ACK，
烧满 `streamOpenTimeout` 后失败—— 无日志、无 reason、不重建。
救场的是 15s keepalive tick 的兜底 `Close()`，但那之前是全盲窗口。
**这就是"死了但没有任何提醒和事件"最贴近的机制。**

### 2.4 记忆笔记里一句错话已经更正

`.memory/notes/p2p-relay-rebuild-secure-poison.md` 曾写 keepalive 经过
`pc.kill → killSession`。已按上述链路验证为错并更正：keepalive
关 underlay 到 `relayKCPStream.Close()` 为止，`peerConn` 全程没被碰到。
本 spec 依赖更正后的版本。

### 2.5 churn 计数器 A 路径不累积（前置 bug）

`e.peerConn` 在换 adapter 时接续了 `sessAt` / `relayRebuilds` /
`relayRebuildPeers` / `lastEndReason` / `storm.carryTo`，但**没接续
`churn` / `churnFrom` / `churnTripped`**。A 路径（反复被 kill、
反复换 adapter）每换一次清零，churn 闸永不触发。两击状态同属
pair 级状态，必须同样接续 —— 这是本设计的 Task 1，也是既有 latent bug 的修复。

## 3. 交付切片

- Task 1（前置）：churn 接续 + 回归测试。独立可合。
- Task 2（死亡信号）：`acceptLoop` 的 `"derp"` 退出接引擎，先 `Close()` 再上报，
  pair 活性门控下立即 `ensureSession`。砍掉 18s 的主体。
- Task 3（watchdog）：每 pair 一个 watchdog goroutine + ticker，
  两击升级：`reasonRelaySilent` 只杀 mux，常静默才 `reasonLinkLost` 杀 pair。
- Task 4（读法）：reason 新值进 `sessionEndReason` 封闭集注释与
  `2026-10-08-p2p-peer-down-reading-the-logs.md`，加一条 doctor 建议行。
  不新增 Status 字段，不加新 RPC（沿用已交付的 peer-down 计数）。

## 4. 方案

### 4.1 Task 1：churn 接续（前置，无争议）

在换 adapter 的同一处（接续 `storm.carryTo` 的相邻行）加上：

- `pc.churn / churnFrom / churnTripped = dead.churn / churnFrom / churnTripped`。
- 回归测试：连杀两次跨 adapter，`takeChurnTripped` 仍按 pair 级窗口累计，
  A 路径第二次 kill 后计数为 2 而不是 1。
- 不改 `resetsPairKCP`、不改 reason 封闭集、不改任何阈值。

### 4.2 Task 2：死亡信号——复用 `acceptLoop` 退出，零新 goroutine

事实：`startAccept` 对**每个** relay mux 会话、两种角色都起 `acceptLoop`；
`AcceptStream` 的四条错误臂（socket read error / proto error / die /
`ErrTimeout`）全部等价于"会话结束"。`ErrTimeout` 臂在本仓永不激活
（无 `AcceptDeadline`），三条错误臂都意味着会话结束。`notifyReadError` /
`notifyProtoError` **不关 `die`** —— 见 §2.3 的说谎窗口。

改动（只动 `"derp"` 分支，direct 分支原样）：

1. **先 Close 再上报**：退出路径上 `if !sess.IsClosed() { sess.Close() }`。
   `Close` 幂等（`dieOnce`，重复调用返回 `io.ErrClosedPipe`），但用
   `IsClosed()` 守一下保持安静路径零开销。这一步把不变量
   "会话结束 ⇒ `IsClosed()`" 修回来，否则 `ensureSession` 的 `replaced`
   分支永远进不去、重建压根不发生。
2. **去重**：回调进引擎时先读 `pc.mu` —— 若 `pc.closed` 已置（kill 路径：
   `killSession` 先置 `closed` 才 `sess.Close()`），说明 kill 已发日志、
   重建走 `e.peerConn` 的 A 路径，handler 直接返回。`pc.accepting == sess`
   的清理沿用 `startAccept` 的既有 defer。
3. **门控重建**：非 kill 死亡时，读 pair 活性：`freshestRecv` 在窗口
   （`relayLiveWindow`，初值 6s，见 §5.2）内 → 立刻 `ensureSession(false, false)`
   （不打洞、不等握手；`onDirectInbound` 已有"回调 goroutine 里调
   `ensureSession`、可拿 `pc.mu`、可 dial relay"的先例）。这就是 B 路径
   （自死重建）的即时触发：同一条 `replaced` 分支、同一行带
   `downFor`/`silentFor` 的重建日志（`relayReason` 为空=静默判死，
   语义与已交付文档一致）。
4. pair 不新鲜 → **什么都不做**，留给 Task 3 的 watchdog。
   在死 pair KCP 上重建只会产出 15s 后再死的会话 → 重建循环 → 撞 churn 闸。
   门控就是刹车。

新增事件行（一行，Debug，与既有行同级）：
`peer relay session ended`，字段：`peer`、`err`（acceptLoop 的返回错）、
`closed`（是否走了 kill 去重短路）、`pairFresh`（门控判决）。
它填的是 §2.3 窗口的"全盲"—— 之前这里是零输出。

### 4.3 Task 3：relay idle watchdog——每 pair 一个 goroutine，两击升级

为什么不能复用读路径：kcp-go 的 readLoop **遇任何读错误永久退出**，
tick 一旦进 `relayPacketConn.ReadFrom` 就会杀死 KCP reader；
而 `pumpRelay` 是纯三路 select、无 tick 源。所以 watchdog 自带
`ticker`，与 `pumpRelay` / `pumpDirect` 同级（每 pair 一个，
生命周期挂 `p.done`，`shutdown()` 负责收）。

判定基础（§2.2 的结论）：健康链路必有双向 3s NOP，`lastRelayRecv`
（`readRelay` 成功返回处盖戳）超过阈值即真故障。阈值
`relayIdleWindow` 初值 **6s**（§5.2 论证）。

两击（Q2 决议），用 `pumpDirect` 的 `idleFired` 同款 episode latch：

- 入站 relay 数据报到达 → 关闭 episode，strike 清零。
- episode 内第一次超阈（strike 1）：`killSession(err, false, reasonRelaySilent)`。
  clean death（`resetsPairKCP` 不含此值，见 §4.4）—— pair KCP 存活、
  key 复用，给还活着的 KCP 一次便宜机会。
- episode 延续、即重建后 `lastRelayRecv` 仍陈旧（strike 2）：
  `killSession(err, false, reasonLinkLost)` —— `reasonLinkLost` 已在
  `resetsPairKCP` 内，受 H1（`resetsPairKCPFor` 的 direct 存活抑制）约束，
  pair 真重置。`dropRelayKCP` 删 pair，下一次 build 拿全新 KCP session。

证据行（watchdog 自己的 Debug 行，不进 kill 行）：
`relay path silent`，字段：`peer`、`silentFor`（watchdog 实测的
**relay 面**静默，注意与 kill 行里 `freshestRecv` 合并值的区别）、
`strike`（1/2）。kill 行照常由 `killSession` 发。

### 4.4 reason 封闭集：只加一个值

`sessionEndReason` 保持封闭（注释原文：新值是可观测性变更）。
只新增 `reasonRelaySilent = "relay-silent"`（watchdog 第一击）。
第二击复用既有 `reasonLinkLost`—— 它已在 `resetsPairKCP` 与
`relayChurnReason` 内，H1 抑制、churn 计数、storm 归因全部自动生效，
不复制任何分支。

`resetsPairKCP` 的 switch 不加分支：未列出的 reason 即 clean death，
pair 存活—— 这正是第一击要的语义，靠"不加"实现。

### 4.5 Task 4：读法（只加文档与 doctor 建议，不加数据）

- `2026-10-08-p2p-peer-down-reading-the-logs.md` 加一节：`relay-silent`
  两击序列的读法（strike 1 行 + kill 行 + strike 2 行 + 最终重建行），
  以及 `silentFor` 在 watchdog 行（relay 面实测）与 kill 行
  （`freshestRecv` 合并值）含义不同的说明。
- doctor 加一条建议行（`sessionEndReason` 封闭集的注释同步）：
  peer 的重建行出现 `relay-silent` strike 2 即"relay 路径真断过一次"。
- 不新增 Status 字段、不加 RPC（v1 的 `SessionDownTotal`/`SessionDownMax`/
  `LastRebuildAge` 已够用），不改 `PeerDiagnostics`。

## 5. 关键语义

### 5.1 新旧行的配对规则（沿用已交付读法，只加两行）

- `peer relay session ended`（Task 2）是**死亡的即时上报**；
  随后同一 `gen` 邻域的 `relay session rebuilt` 是同一事件的重建记录。
  两者之间不再有 ~18s 的沉默—— 这是本设计唯一的延迟断言。
- `relay path silent strike=1`（Task 3）+ 紧随的 kill 行（`relay-silent`）
  是第一击；`strike=2` + kill 行（`link-lost`）是第二击。
  strike 2 之后必然跟一个 pair 真重置（`relay kcp pair reset`）。

### 5.2 数字的初值与依据

- `relayIdleWindow = 6s`：健康链路 3s 一次 NOP，6s = 容忍丢一个
  ping 周期再判。远小于 smux 的 15s（提前 ~9s），又不会把
  "丢一个 NOP" 当死亡。与 `directUnderlayIdle = 6s` 同值、同论证，
  不是巧合。
- `relayLiveWindow = 6s`（Task 2 门控）：与 watchdog 同阈值——
  门控问的是同一个问题（"pair 还活着吗"），答案应当一致。
- 两个值都走 `resolveSmuxTimeouts` 同款配置形状（`apply.go` 已有
  `timeouts.smux` 的解析先例），默认 6s，不加新顶层 section。

### 5.3 与 churn 闸的关系

Task 2 的门控重建走 B 路径（`ensureSession` 的 `replaced` 分支），
`noteBuildLocked` 照常计数—— 门控的作用是**不让死 pair 进计数**，
而不是绕过计数。Task 1 修好接续后，churn 闸对 A/B 两条路径都生效；
watchdog 的 strike 2（`link-lost` kill）本身也进 churn 窗口，
与 `reconnectRelay` 的升级链衔接，不另起一套。

## 6. 测试

TDD，每条先红后绿（`GOWORK=off`，`internal/host` 单包跑，
见既有测试约束）：

1. `TestChurnSurvivesAdapterSwap`（Task 1）：两次 kill 跨 adapter，
   `takeChurnTripped` 按 pair 级窗口累计，A 路径第二次 kill 后计数为 2。
2. `TestSessionEndReportedWithoutKill`（Task 2）：关掉一个无 kill 的
   会话（模拟 §2.3 窗口：`notifyReadError` 后 `IsClosed()==false`），
   handler 先 `Close()` 再上报；断言 `IsClosed()` 为 true、
   `peer relay session ended` 行存在、且 `pc.closed` 仍 false。
3. `TestDeathHandlerDedupsAgainstKill`（Task 2）：有 kill 在先的死亡，
   handler 走 `pc.closed` 短路，不调 `ensureSession`（计数器断言零重建）。
4. `TestDeathHandlerRebuildsOnFreshPair`（Task 2）：pair 新鲜时死亡
   立刻重建：重建行带 `downFor`（≈0，因为死亡即重建）与 `silentFor`
   （≈15s），`relayReason` 为空。
5. `TestDeathHandlerStandsDownOnStalePair`（Task 2）：pair 陈旧时死亡
   不重建（零 `ensureSession` 调用），死亡只留 `ended` 行。
6. `TestRelayWatchdogFirstStrikeKillsMuxOnly`（Task 3）：
   relay 静默超 6s，第一击 kill 行 reason 为 `relay-silent`，
   且 pair 未被删（`relayKCPPairGet` 仍在）、key 复用（`secureReuse=true`）。
7. `TestRelayWatchdogSecondStrikeResetsPair`（Task 3）：
   episode 延续，第二击 kill 行 reason 为 `link-lost`，
   且 pair 被删（下一次 build 是新 KCP session）。
8. `TestRelayWatchdogRearmsOnTraffic`（Task 3）：episode 内来一个
   relay 数据报，strike 清零，不 kill（latch 回归测试）。
9. `-race` 全绿是门禁（`CGO_ENABLED=1 GOWORK=off go test -race -p 1 ./...`）。

故障注入用既有 `FaultsConfig`（`dropData` 含 NOP 的形状正好是
"relay 面全静默"），不新增 knob。

## 7. 验收

- [ ] Task 1 合入后：A 路径 kill 两次，churn 计数为 2（测试 1）。
- [ ] Task 2 合入后：一次无 kill 的静默死亡，从死亡到重建行 < 2s
  （之前 ~18s），且 `ended` 行先于重建行（测试 2/4）。
- [ ] Task 3 合入后：一次 relay 全静默，6s 左右出现 `strike=1` +
  `relay-silent` kill，重建后仍静默则出现 `strike=2` + `link-lost`
  kill + `relay kcp pair reset`（测试 6/7）。
- [ ] 误判回归：健康空闲 peer（双向 NOP 正常）跑 5 分钟，
  零 `strike`、零 `ended`、零非预期重建—— watchdog 与门控对
  健康链路完全透明。
- [ ] `GOWORK=off go build ./...` 与
  `CGO_ENABLED=1 GOWORK=off go test -race -p 1 ./...` 全绿。

## 8. 非目标

- 不碰 direct 面（Q3 决议）：`onDirectIdle`、`onDirectInbound`、
  direct 的 `acceptLoop` 日志分支原样。
- 不缩 `smuxKeepAliveTimeout`（15s 地板，`engine.go` 注释已论证；
  混合机群里还有 10s ping 的旧 peer）。
- 不新增 Status 字段 / RPC / gRPC（peer-down v1 的计数已够用）。
- 不给 `relayPacketConn` 加真 deadline（kcp-go readLoop 的
  "遇错永久退出"决定了 tick 不能进读路径—— 见 §4.3）。
- 不改 `resetsPairKCP` / `relayChurnReason` 的分支（新语义靠
  "不加"实现，见 §4.4）。

## 9. 待决策项（写完 spec 剩下的唯一开放点）

- `relayIdleWindow` / `relayLiveWindow` 的 6s 初值是否需要在真机上
  先测一轮 NOP 抖动再定：loopback 上 3s NOP 极稳，蜂窝弱网下
  NOP 本身可能丢包延迟。建议实现后先用默认 6s 跑 e2e 的
  `silenceFor` 形状（既有 `FaultsConfig.silenceFor/silenceEvery`
  正好是 18s 级故障），看 strike 误报率再定终值。
  —— 如需调整，只改默认值与配置解析，不动状态机。

## 10. 自查

- [ ] 无占位符：所有阈值（6s/6s）、所有行名
  （`peer relay session ended` / `relay path silent`）、
  reason 值（`relay-silent`）都已定，无 TODO。
- [ ] 一致性：§4.2 的"pair 不新鲜→什么都不做"与 §4.3 的
  "episode 延续→strike 2" 衔接—— 前者留下的死会话由后者收；
  §4.4 的"不加分支"与 §2.5 的 `resetsPairKCP` 现状一致
  （`relay-silent` 不在 switch 内 = clean death）。
- [ ] 范围：Q1（门控重建）/ Q2（两击）/ Q3（只 relay）三项决议
  在 §3–§4 都有对应落点，无决议外扩散。
- [ ] 歧义："立刻 `ensureSession`"指 Task 2 handler 内同步调
  `ensureSession(false, false)`（`onDirectInbound` 先例），
  不是另起队列；"episode 延续"指重建后 `lastRelayRecv` 仍陈旧
  （测试 7 断言），不是计时器到期。
