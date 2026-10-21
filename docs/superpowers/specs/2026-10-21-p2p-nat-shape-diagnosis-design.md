# p2p NAT 形状诊断（S1+S2）— design

- 日期：2026-10-21
- 状态：待评审（已过 builder check，修订见 §11）
- 关联：`.memory/notes/p2p-nat-type-detection-eval.md`、`p2p/docs/2026-09-30-p2p-peer-diagnostics-design.md`
- 关联记忆：[[p2p-nat-type-detection-eval]]、[[hub-udp-egress-ip-rotation]]、[[p2p-seedaddr-test-was-untracked-wip]]、[[wisper-peer-row-rtt-order-trace-times]]、[[p2p-link-sessionscoped-tun-coupling]]

## 1. 意图（why）

"这个 peer 为什么还在 relay 上"是 p2p/wisper 现场调试最贵的问题。两次真实根因排查都因为缺
"NAT 形状"信息而走错路（[[hub-udp-egress-ip-rotation]]：先误判"hub 出口 IP 逐包轮换"，
再误判"手机 NAT 按目的地换 IP 是根因"，两次结论都被实测推翻）。

本轮**不新增 NAT 探测能力**。p2p 早已在计算这个信号，只是把它当噪音丢掉了：

- 对端应从它通告的端点应答，实际却从另一个端点应答（`internal/host/direct.go:1494-1498`
  的注释直写 "a per-destination NAT maps a different public endpoint per destination"）——
  **判定已在做，只用于转向重传，没有留痕**；
- 直连"只发不收"（`internal/host/relaykcp.go:968 directOneWayDead`）—— **已实现**，但结论词
  是"路径死了"，没有归因。

所以本轮的目标是：**把已经在算的两个事实，变成 per-peer 的一句人话结论**，让 wisper 的
`/api/p2p/doctor`（进程内调用）不用翻日志就能回答"这一对是什么形状、为什么直连没成"。

## 2. 目标

- G1：`PeerDiagnostic` 带上 pair 级结论词 + 两个支撑事实（in-process only）。
- G2：doctor 输出一行 NAT 形状结论（每个 peer 一条 + 一个 host 级汇总），**仅进程内调用方可见**
  （见 §3、§7）。
- G3：punch trace 里留下"对端从非通告端点应答"这一行（trace 在 wire 上 ⇒ CLI 的原始 trace
  里也能看到，可 grep）。
- G4：纯诊断，**零行为变更**：不改打洞决策、不改 wire 协议、不改配置、不加依赖、不扩 proto。

## 3. 非目标（明确不做）

- **不做完整 RFC 3489/5780 分类**（不区分 full-cone / restricted-cone / port-restricted）。
  理由：对 p2p 的打洞策略没有影响 —— 互撞本来就要求双方同时发，cone 与 restricted 的差别
  不改变任何决策。
- **不做 host 级 NAT 标签**（cone/symmetric 的主动探测，需要第二个 STUN 目的地）。
  理由：p2p 的握手是自适应的（从回包学到对端真实端点再改拨），**前置分类不必要**；
  frp 需要前置分类是因为它的策略（角色分配、端口段猜测、TTL 探测）必须提前知道形状。
  详见 [[p2p-nat-type-detection-eval]]。
- **不做"我方是 per-destination"的判定**。我们的映射由 NAT 改写，本地不可知；只有对端能看到
  我们探测包的源地址 ⇒ 需要对端回报（wire 变更），留作后续（§10）。
- **不改 gRPC proto**。proto 是冻结的（`p2p/status.go` 各处 "in-process only: the gRPC
  transport's proto is frozen"），本轮新字段同样 in-process。代价见 §7。
- **不把 trace 措辞当 API**。trace 行只是给人看的；doctor 不从 trace 文本反推结论
  （否则 CLI 需要靠解析文本才能给出结论，代价是措辞从此冻结）。CLI 侧只多一行原始 trace。

## 4. 反目标（做到这些算失败）

- **不猜一个证明不了的 NAT 类型**。结论词只覆盖证据支持的范围，宁可说"per-destination
  或映射变了"也不说"symmetric NAT"。
- **不对着不存在的路径报时长**。F2 的时长只有在 latch 归属于**当前** underlay 时才报（§5）。
- **不把 in-process 的新字段说成 wire 上可见的**。任何"前端/CLI 能看到"的结论都要先验证
  读取路径。
- **不动已稳定的打洞路径**。只加旁路观测，不改 seed 握手、不改候选交换、不改 KCP。

## 5. 事实与判定（已核实，带出处）

### F1 —— 对端从"它没通告过的端点"应答

- 位置：`internal/host/direct.go:1366` 的 `seedHandshakeUDPToken(f.sock, dial, seedTimeout)`。
  它返回 `(token, answer, err)`，`answer` 是**回显我们 token 的那个包的源地址**
  （`direct.go:1491`），即对端"它真正可被到达的端点"；`dial` 是我们拨的那个通告端点。
- 判定：`answer` **不属于**对端本轮通告的候选集合（用 `cands` 里最新鲜的一份，已经过
  `fresherCandidates` 刷新）⇒ F1 成立。
- 必须用"集合成员"而不是"≠ dial"：同 NAT hairpin 规则下我们可能拨对端的**本地**地址
  （`direct.go:1357-1362`），而它从**公网**端点应答 —— 公网端点**在**通告集合里 ⇒ 不是 F1。
  （注意：这只是 `containsAddr` 的一个合法用例；**不能**当成"hairpin 一定不是 F1"的证明 ——
  per-destination 映射下 hairpin 的应答端点同样可能落在通告集合外。）
- 家庭成员比较必须复用现有的 `sameAddrPort`（`directunderlay.go:282`），它会 unmarshal
  v4-in-v6，避免 `::ffff:a.b.c.d` 与 `a.b.c.d` 被判成不同。
- **含义**：对端的映射随目的地而变（per-destination NAT），或者它在 STUN 探测之后发生过
  rebind。两者**症状相同、补救相同**（用观测到的端点），所以结论词必须同时涵盖。
- **不蕴含**：对端不可达。它恰恰是 p2p 已经能 work 的形状 —— learned 地址机制
  （[[p2p-seedaddr-test-was-untracked-wip]]）正是为此而生（k3s per-destination 端口 NAT：
  5976 次 0 成功 → 187/191 成功）。
- **契约**：sticky —— 取**最近一次成功轮次**的观测；失败的轮次没有观测，不清除旧值
  （"为什么这个 peer 还在 relay 上"正是要看它）。因此必须带一个"观测于多久前"的时间戳，
  否则会把几小时前的形状说成当前形状。

### F2 —— 直连只发不收

- 位置：`internal/host/relaykcp.go` 的 `directOneWayDead(now, u)`，窗口
  `directOneWayWindow = 60s`（`relaykcp.go:140`），latch 时刻存在 `oneWayAt`
  （`relaykcp.go:297`，受 `p.mu` 保护）。
- 现状：只在 `relaykcp.go:1032` 用来判定"这条路不再承载"，**从不作为诊断暴露**。
- **含义要克制**：单向直连是**路径健康**信号，不等于 NAT 形状。它的常见成因是会话层半死
  （[[p2p-half-dead-session-after-netswitch]]：底层 UDP 双向健康、心跳互换，是会话层半死），
  e2e 里也有一条例行的单向注入场景（`tests/e2e/run.sh` 的 `arm_oneway_fault`）。
  ⇒ F2 只能作为**事实**暴露，不能被解释成"NAT 形状"（因此在报告里它单独占一行 `path health:`）。
- **粘性（2026-10-21 修订，用户拍板）**：一次单向**事件**（episode）连同它的**时长**与
  **结束时刻**被记下来，**在路径退役之后仍然保留**。
  理由：本特性存在的意义是回答"这个 peer 为什么还在 relay 上"，而**路径被判死、peer 回落
  relay 的那一刻正是答案最该在的时刻** —— 早先"只报活路径"的规则让事实恰好在那一刻消失。
  ⇒ 报告的说法带时态：还在发生 ⇒ "has been one-way for 3m0s"；已经结束 ⇒ "was one-way for
  3m0s, 40s ago"。**时长永远带日期**（age 说明它是什么时候的事），所以不是"对着一条不存在
  的路径报时长"，而是"报一件发生在什么时候的事"。
- **只报"算数"的事件（2026-10-21 复核后裁定）**：事件必须**达到过判死窗口**（或仍在进行中）
  才被上报。一次没能撑满窗口就结束的单向，是接收计数器的抖动（健康路径也常出现），不是
  "路径被判死"这件事 ⇒ 不上报。否则一个 1 秒的抖动会让该 peer 此后**永远**被标成 one-way。
- **单一时钟域（2026-10-21 复核后裁定）**：事件的开始/结束/读取全部用**真实时钟**，
  且读取在**写戳的同一把锁内**取 ⇒ 时长与 age **不可能为负**（否则时态会错、进行中的事件
  甚至会被漏报）。形状窗口的判定也用真实时钟（单测改用**短窗口 + 真实 sleep**，不再用
  合成时钟 —— 混用两个时钟域会算出负时长）。
- **陈旧 tick 守卫（2026-10-21 复核后裁定）**：`directOneWayDead` 只接受**当前安装的
  underlay** 的 tick。一条正在退役/被替换的 pump 仍可能在 tick 里，而它开的 episode
  **没有任何人能结束**（两个结束路径都不认识那个 underlay 了）⇒ 报告会说"has been
  one-way 3 小时"，并把真正有价值的那条事实覆盖掉；更糟的是它还会让后来的新路径对着
  陈旧的起点算窗口 ⇒ 重新引入"新路径首个 tick 即被判死"的抖动。
- **陈旧性（随之改写）**：`oneWayAt` 只在 `directOneWayDead` 内部被写/清，
  `setDirectUnderlay`（`relaykcp.go:838-871`）**不重置它** ⇒ 换掉一条因单向被判死的直连之后，
  latch 仍带着旧时间戳 ⇒ **新 underlay 若先发后收，会对着陈旧 latch 重新 latch，
  `now.Sub(oneWayAt) >= window` 立刻为真 ⇒ 新路径第一个 tick 就被判死**。
  ⇒ 事件化改造**顺带修掉这个既有缺陷**：事件在 underlay 被替换/退役时**结束**（记下结束时刻），
  于是新 underlay 的第一次单向只会**开一个新事件**（窗口从零算），不会被旧时间戳立刻判死。
  这是**行为变更**（一个 bug 的修复），必须有红→绿测试钉住（§8）。



### 派生结论词 `NATShape`

两个事实派生出**一个**词 —— 是**查表**（四种组合），不是优先级级联：

| `NATShape` | F1 | F2 | 含义 |
|---|---|---|---|
| `""` | 否 | 否 | 未观测到（没打过洞，或打洞正常） |
| `peer-endpoint-differs` | 是 | 否 | 对端从它没通告过的端点应答 ⇒ 它的映射随目的地变或变过 |
| `one-way` | 否 | 是 | 直连只发不收（**路径健康**问题，不是 NAT 结论）—— 事件可能在进行中，也可能已经结束（见 §5 F2 的粘性） |
| `one-way+peer-endpoint-differs` | 是 | 是 | 见下 |

两者都成立时的归因：**F1 成立 ⇒ 对端的通告端点对我们不可用 ⇒ 我们发过去的包被对端 NAT
丢弃 ⇒ 若是单向，锅在对端侧**；**F1 不成立但 F2 成立 ⇒ 对端是从它通告的端点应答的
（它的映射对我们有效）⇒ 单向在我们这侧**（我们通告给它的端点被我们的 NAT 丢弃）。

## 6. 落点（改动清单）

### 6.1 `p2p/status.go` —— `PeerDiagnostic` 新增四个字段（in-process only）

| 字段 | 类型 | 含义 |
|---|---|---|
| `NATShape` | `string` | 结论词，取值域见 §5；`""` = 未观测到 |
| `NATObservedAge` | `time.Duration` | F1 观测距今多久；`0` = 从未观测到 F1 |
| `OneWayFor` | `time.Duration` | 直连单向**事件**的时长（事件进行中 = 已经多久；已结束 = 曾经持续了多久）；`0` = 没有事件 |
| `OneWayAge` | `time.Duration` | 该事件**结束**距今多久；`0` = 事件仍在进行 |

- **不新增"对端应答端点"字段**：现有的 `PeerDiagnostic.PeerAddr` **就是**它 ——
  `markUp(sock, answer, token)`（`direct.go:1390`）注册的是应答端点。
  ⇒ 顺手修两条**已经过时**的注释：`p2p/status.go:22`（"the endpoint **dialled**"）和
  `direct.go:971`（"the peer's **dialed** endpoint"）—— 它们在 learned 地址修复后就错了。
  **只改注释，不改语义**（`PeerAddr` 的语义保持"应答端点"；改语义会波及
  `engine.go:1002`、`engine.go:1081-1082` 的 `openedStream.PeerAddr()` 和 doctor 的
  "peer addr" 行，而 proto 上带着 `peer_addr` ⇒ 改了会让 CLI 的那一行含义漂移）。
- 新字段的注释要写清：结论词的取值域、每个值背后的**证据**、以及为什么
  `peer-endpoint-differs` 不蕴含"打不通"（learned 地址机制能 work）。

### 6.2 `internal/host/direct.go` —— 记录 F1

- 在 punch 轮次拿到 `answer` 之后（`direct.go:1366` 之后、`markUp` 之前）判定：
  `announced := peerV4` 或 `peerV6`（按本轮族取），`mismatch := !containsAddr(announced, answer)`。
- 新增**小纯函数**便于单测：`func containsAddr(list []netip.AddrPort, addr netip.AddrPort) bool`，
  比较用 `sameAddrPort`（unmap v4-in-v6）。通告集合的元素是 `candidate.addr`
  （`candidate` 结构体，`direct.go:183`），取地址时过一层。
- 记录到 `directConn`：`peerAnsweredFrom netip.AddrPort` + `peerEndpointDiffers bool` +
  `peerEndpointObservedAt time.Time`，受 `dc.mu` 保护（该互斥量已在用它保护 `dc.mine`，
  `direct.go:1263-1265`）。
- trace 行（**只在 mismatch 时发**）：`dc.noteRound("peer answered from %s (not announced)", answer)`。
  ⚠️ trace 文本被逐字解析（[[wisper-peer-row-rtt-order-trace-times]]：`lastBackoffWait` 切
  `backoff ` 前缀 + `ParseDuration`）⇒ **新增行可以，改现有行不行**。
  `TestPunchTraceRing`（`direct_test.go:2389-2420`）喂的是合成行，不需要改。
- F1 是**每轮**观测，后来的轮次可能不再异常 ⇒ 取**最近一次成功轮次**的值；
  新的成功轮次若不匹配 ⇒ **覆盖**旧值（保留最新观测，避免报告一个已经过去的形状）；
  失败的轮次没有观测 ⇒ **不清除**旧值（sticky，见 §5）。

### 6.3 `internal/host/relaykcp.go` —— 暴露 F2

- `directOneWayDead` 在**事件开始**的那一刻（此前没有进行中的事件）记下**是哪个 underlay**
  开的：`p.oneWayU = u`。为此它的签名要加一个 underlay 参数（`directOneWayDead(now, u)`）——
  唯一生产调用点 `relaykcp.go:1032` 与 `direct_oneway_test.go` 的 5 处调用需要跟着改。
- pair 的单向状态从"一个 latch"改成"**一个事件**"（受 `p.mu` 保护）：
  - `oneWayStart time.Time` —— 事件开始时刻（零 = 从未发生过）；
  - `oneWayEnd time.Time` —— 事件结束时刻（零 = 仍在进行）；
  - `oneWayActive bool` —— 事件是否仍在进行；
  - `oneWayReached bool` —— 事件是否**达到过判死窗口**（只有它才被上报）；
  - `oneWayU *directUnderlay` —— 事件属于哪个 underlay。
  事件在三种情况下结束：形状不再成立（`directOneWayDead` 的"无动静/有回包"两个分支）、
  underlay 被替换（`setDirectUnderlay`）、underlay 被退役（`clearDirectUnderlayIf`）。
- `directOneWayDead(u *directUnderlay) bool` —— **不再接受外部时钟**（真实时钟域），并且
  **只接受当前安装的 underlay** 的 tick（陈旧 tick 守卫，见 §5）。
- 新增 `func (p *relayKCPPair) directOneWayEpisode() (length, age time.Duration)`：
  事件仍在进行 ⇒ `(now - oneWayStart, 0)`；已结束且达到过窗口 ⇒
  `(oneWayEnd - oneWayStart, now - oneWayEnd)`；未达到过窗口的抖动 ⇒ `(0, 0)`；从未发生 ⇒ `(0, 0)`。
  读这些字段要持 `p.mu`，**时钟在锁内取** ⇒ 时长与 age 不可能为负。
- **行为变更（修 bug）**：因为事件在 underlay 被替换/退役时**结束**，新 underlay 的第一次
  单向只会**开一个新事件**（窗口从零算），不会再对着陈旧时间戳被判死（§5 F2 的陈旧性段）。
  ⇒ 必须有红→绿测试钉住（§8）。

### 6.4 `internal/host/engine.go` —— 装配诊断

- 在 `directs` 循环里（`engine.go:327-358`）填四个新字段：F1 来自 `directConn`，F2 来自
  `e.relayKCPPairGet(peer)`（`fillPairDiag` 已经在拿这个 pair，`engine.go:367`）。
- 派生 `NATShape` 的函数要**纯**、可单测：`func natShape(differs bool, oneWay bool) string`
  —— 四种组合的查表。
- 没有 `directConn` 的 peer（纯 relay）⇒ 字段留零 ⇒ `NATShape == ""`。

### 6.5 `p2p/doctor/doctor.go` —— 输出

- `peerVerdict`（`doctor.go:324`）在 `direct` / `failed` / default 分支上追加 NAT 短语：
  - F1：`peer answers from 1.2.3.4:51000, an endpoint it did not announce (its mapping varies by destination or changed, observed 2m ago)`
  - F2：`the direct path has been one-way for 3m0s (we send, nothing comes back)`
- 新增 host 级汇总行（放在 `verdicts()` 里，`doctor.go:249`）：只统计**有 F1 观测**的 peer，
  形如 `NAT shape: 1 of 2 peers answer from an endpoint they did not announce`。
  `--peer <key>` 收窄时，只描述那一个 peer。没有任何观测 ⇒ 整行省略。
- 措辞纪律：F2 **不得**被写成 NAT 结论（§5）。

### 6.6 不改的东西

- `internal/stun`、候选交换、seed 握手协议、caps 位、配置、gRPC proto、`directOneWayDead`
  的判死行为、打洞的任何决策。

## 7. 可见面（wire vs 进程内）—— 必须在实现时守住

- `p2p doctor` **CLI 是 gRPC 客户端**（`cmd/p2p/doctor.go` 的 `fetchStatus` → `statusFromReply`
  逐字段从 wire 回复重建 `p2p.Status`），**不是**进程内 ⇒ 新字段在 CLI 里结构性地恒为零。
  doctor 包自己的文档写明了这一点（`doctor/doctor.go:7-9`："the `p2p doctor` CLI (over the
  gRPC control plane) and wisper (in-process…)"），`Options.InProcess` 就是为区分这两者存在的。
- ⇒ **进程内调用方（wisper 的 `/api/p2p/doctor`）能看到结论词**；CLI 看不到。
  仓库先例：`docs/superpowers/specs/2026-10-08-p2p-peer-down-events-design.md:61`
  —— *"新行与 relay churn 同样 in-process only，`p2p doctor` CLI 看不到 … 验收时不要因为 CLI
  看不到就判成「功能没生效」"*。
- ⇒ **wire 调用方必须说"没被报告"，不能装作没发生**：doctor 用 `opts.InProcess` 区分，
  `false` 时输出 `NAT shape: not reported by the control plane`（沿用 `relayRTT` 的既有做法，
  `doctor.go:369`）。`Options.InProcess` 的语义已在 `doctor.go:43-50` 写明，CLI 保持 `false`
  （`cmd/p2p/doctor.go:63` 有显式注释）。
- CLI 侧仍能拿到**原始 trace 行**（trace 在 proto 上）⇒ 现场排查可 grep。

## 8. 约束与坑

- **trace 文本是 API**：新增行可以改，现有行不能改（[[wisper-peer-row-rtt-order-trace-times]]）。
- **注释只写英文**（[[english-only-comments]]）。
- **`p2p/status.go` 的公开 API 字段要写"这个值代表什么证据"**，因为 `PeerDiagnostic` 的读者
  会拿它当结论（这正是本轮存在的理由）。
- **proto 冻结**：新字段 in-process only（§7）。
- **别把它当门控**：结论词是诊断，不是"要不要打洞"的判据（§3、§4）。
- **`PeerAddr` 的注释是错的**（§6.1），本轮顺手修，但**不改语义**。

## 9. 测试策略

1. **单测（纯函数）**
   - `containsAddr`：命中通告集合 / 未命中 / v4-in-v6 等价 / hairpin（拨本地、答公网 ⇒ 不算 F1）。
   - `natShape`：四种组合 ⇒ 词表取值。
   - F1 判定在 `directConn` 层的注入测试（喂 answer + 通告集合，断言 `peerEndpointDiffers`
     与 `peerEndpointObservedAt`）。
   - `directOneWayFor`：latch 属于当前 underlay ⇒ 返回时长；latch 陈旧（underlay 已被换掉）
     ⇒ 返回 0。
2. **doctor 输出测试**：沿用 `doctor_test.go` 现有风格（断言行文本），覆盖
   "F1 ⇒ 有短语"、"F2 ⇒ 有短语且措辞不是 NAT 结论"、"都没有 ⇒ 无短语"、
   "wire 调用方（`InProcess: false`）⇒ 'not reported by the control plane'"。
3. **e2e**：`tests/e2e` 的 netns 拓扑里两侧同桥、无 NAT（`run.sh` 只有单向故障注入用的
   iptables DROP，没有 masquerade）⇒ 天然不产生 F1 ⇒ **反向断言：trace 里不得出现
   "not announced" 行**。trace 在 proto 上（`tests/e2e/helper/main.go:96` 的
   `reply.GetPeerDiagnostics()`），所以这条断言在 wire 层可表达。
   ⚠️ 新字段本身 e2e 看不到（proto 冻结），别写成对诊断字段的断言。
   真正制造 F1 需要给 e2e 拓扑加一个 SNAT 命名空间（`--random-fully` 的 masquerade），
   属于新增拓扑，本轮**不做**（§10）。

## 10. 后续（本轮不做，按优先级）

0. **疑似既有缺陷（新 underlay 对陈旧 `oneWayAt` 重新 latch ⇒ 首个 tick 即被判死）**：
   单独查证 + 修（修法大概是在 `setDirectUnderlay` 里重置 latch，但那会改变行为，需单独评审）。
   它属于 [[p2p-link-sessionscoped-tun-coupling]] 记的那族"半死路径"问题。
1. **"我方是 per-destination"**：需要对端回报它看到的源地址（wire 变更：seed echo 加
   4–20 字节，或走控制帧）。有了它才能给出对称的 pair 级结论。
2. **host 级 NAT 标签**：客户端加普通 RFC 5389 模式 + 第二个 STUN 目的地（公共或自建），
   得到任意时刻可查的 cone/symmetric。**前置必需性已被证伪**（§3）。
3. **e2e 的 NAT 拓扑**：给 `tests/e2e` 加一个带 SNAT 的第三 namespace，制造 F1 的端到端断言。
4. **wisper 前端**：`/api/p2p/doctor` 是进程内的 ⇒ peer 行可直接显示结论词；需要 wisper 侧
   改一行渲染。若将来想让 CLI 也看到 ⇒ 需要 proto 变更（与"proto 冻结"冲突，需单独决策）。

## 11. 评审记录（builder check 的更正，已全部落进本文）

第一版的四处错误（由独立 builder 对着代码核对发现）：

1. **"doctor CLI 是进程内的"是错的** —— CLI 是 gRPC 客户端 ⇒ §7 重写，G2 的可见面收窄，
   并新增"wire 调用方必须说 not reported"的纪律。
2. **新增的"应答端点"字段是重复品** —— `PeerAddr` 已经是它 ⇒ 删掉该字段，改为修两条过时注释。
3. **e2e 看不到新字段**（断言走 proto）⇒ 反向断言改为查 trace 行。
4. **one-way latch 陈旧** ⇒ F2 改为"latch 归属于当前 underlay 才报"，并把疑似既有缺陷单列 §10.0。

另修正：hairpin 例子只作 `containsAddr` 用例、不能当叙述性证明；`NATShape` 是查表不是
优先级；`TestPunchTraceRing` 不需要改（它用合成行）；§8 里 trace 解析的出处指向修正为
[[wisper-peer-row-rtt-order-trace-times]]。

## 12. 留给实现者

- **我已拍板的**：字段名与取值域、四组合查表、比较必须用 `sameAddrPort`、F1 sticky 且带
  观测时间戳、新的成功轮次覆盖旧值、F2 只在 latch 属于当前 underlay 时报、
  纯函数化以便单测、in-process only、wire 调用方说"not reported"、措辞纪律
  （"one-way" 不写成 NAT 结论）、不改 `PeerAddr` 语义、只修其注释。
- **实现者要自己决定的**（文档没规定、且猜错也不致命）：F1 三个字段在 `directConn` 上的
  具体组织方式（三个字段 vs 一个 struct）、trace 行的确切措辞（只要不改现有行）、
  doctor 短语的排版。
- **需要回头找我确认的**：如果实现中发现 F1 与既有语义冲突（例如 `directunderlay.go:224`
  的稳态源过滤已经隐含了同一事实），**以既有语义为准，本文档让位**。
