# p2p 多 DERP 中继：按连接分流的多路径设计

- 日期：2026-10-20
- 状态：待评审
- 关联：`docs/2026-10-05-p2p-kcp-path-migration-design.md`（单 KCP + 双 underlay 迁移）
- 关联：`docs/2026-10-04-p2p-relay-kcp-reliability-design.md`（KCP over DERP）
- 记忆：`.memory/notes/p2p-derp-relay-done.md`、`.memory/notes/p2p-kcp-session-migration.md`

## 1. 背景

现在的 p2p 中继面是**一个 endpoint 一个 `derp` URL、一个 peer 对一条 KCP 会话**：

- `p2p/config.go` 只有标量 `Derp`；
- `engine.client` 只保存一条 `derpclient.Client`，`sendControl` / `peerConn.Write` 都直接落到它；
- 一个 peer 的所有 smux stream 共享同一条 KCP 会话的拥塞窗口和重传队列；
- 直连成功时，同一条 pair KCP 会从 relay underlay 迁到 direct underlay（`relayKCPPair`）。

这带来两个限制：

1. **单点**：中继挂掉时，走 relay 的 peer 全部断，只能等重连或换 URL 重启。
2. **单窗口**：即使有多个中继可用，所有连接仍挤在一条 KCP 上，总吞吐被单个中继/单个拥塞窗口卡住。

目标不是把一条连接拆到多条路上（那需要跨路径重排序，属于另一类方案），而是**让不同的连接走不同的中继**，用多条独立链路把总吞吐叠起来；同时中继故障只影响落在它上面的那部分连接。

## 2. 目标与非目标

### 目标

- 无法直连（或 `direct:false`）的 peer 对，可以同时使用 N 条 DERP 中继；
- 新开的 TCP 隧道流 / UDP datagram link 被分配到其中一条健康链路，多条连接的总吞吐接近各链路可用带宽之和；
- 某条中继故障时：该链路上的连接允许断开，其他链路上的连接不受影响，新连接自动绕开坏链路；
- **直连优先不变**：peer 有活直连时，新连接仍然全部走直连；多中继只服务直连不可用的场景；
- 单中继配置的行为、旧 peer 的行为保持不变。

### 非目标

- 单条 TCP 连接跨多条中继聚合（不做包级 striping、跨路径重排序、MPTCP 式调度）；
- 中继故障时已建立连接的透明迁移（允许应用重连；KCP underlay 迁移仍只服务现有 direct↔relay 切换）；
- 中继之间互相转发 / DERP mesh / 链式中继；
- 自动发现中继、按实时吞吐动态调权（v1 用简单健康度 + 连接数）；
- 改变 DERP 协议或 derper。

### 约束

- v1 要求两端配置**同一组中继**（顺序无关，按 relay identity 去重）；部分重叠留到后续。
- 每个 endpoint 对每个中继保持一条 DERP 连接（同一 node key）。
- 现有单中继配置必须零改动可用；旧 peer 不感知多中继。
- 加密保持端到端；每条链路独立密钥、独立 nonce 序列。

## 3. 核心决策

| # | 决策 | 理由 |
|---|------|------|
| D1 | 采用“按连接分流”（每中继一条完整 pair 链路），不采用“单流多路径” | 满足多连接总吞吐目标，避免跨路径重排序与每路径拥塞控制 |
| D2 | 每条中继 = 独立的 KCP + secure + smux 会话 | 每链路独立拥塞窗口，才能真正叠加带宽；一条链路故障不拖垮其他链路 |
| D3 | 保留现有 primary pair link（可装 direct underlay）并让它承载控制面；额外中继只是 data link | 直连优先与现有迁移模型不变，改动集中在新增链路 |
| D4 | relay identity = base64(DERP 握手返回的 server public key)，不是 URL | 同一中继的多个域名/别名视为同一链路；KCP conv 与密钥标签稳定 |
| D5 | 额外链路的 secure 密钥由同一次 ECDH 握手派生，HKDF info 加入 link tag | 不增加 N 次握手；同一共享秘密派生不同密钥，避免 nonce 复用 |
| D6 | 新连接按 least-in-flight + 加权轮询选链路；打开失败换下一条 | 简单、可解释；避免一条坏链路直接让用户连接失败 |
| D7 | 中继“对端在线”没有服务端 presence，用 `ctrlLinkHello` 在目标中继上做往返探测 | 真 derper 不给开放客户端 PeerPresent（见 `p2p-derper-no-presence`） |
| D8 | v1 不迁移已建立连接 | 用户已接受断开重连；迁移需要跨会话/跨 conv 接管，成本远高于收益 |
| D9 | 数据帧按 KCP conv 分流，而不是按“一个 peer 一个队列” | 同一中继上可能同时存在 primary 与 data link，必须能区分；conv 已在 KCP 头里，无需改 wire |
| D10 | pair 级 ECDH 密钥协议独立于 relay 存活，data link 只从它派生 | 否则 home relay 一挂就会重握手，连累其他中继上的链路；只有对端重启/身份变化才 rekey |
| D11 | home relay 采用“粘性选举”：只在当前 home 故障或对端广告不同 home 时重算 | 避免低 ID 中继恢复造成 primary 反复重建 |
| D12 | `ctrlLinkHello` 是**建链握手**，不是纯探测：收到 hello 的一方先建好自己那半边再回显 | 否则 opener 的数据会打在尚未存在的会话上，首个 stream 黑洞 |
| D13 | TUN/`ip` link 固定走 primary，不参与多中继分流 | `ip` link 是 session-scoped，状态注册绑在 primary 会话上；且单条 tun 属于“单流”，本来就不在目标内 |
| D14 | `peer-absent` 是可重试状态，按退避周期重新 hello | 一次 3s 超时不应让一条中继暗 10 分钟 |

## 4. 架构

### 4.1 relay registry

`engine` 从“一个 client”改为“一组 relay 连接”：

```go
type relayConn struct {
    url    string
    id     relayID        // base64(server public key)，连接建立后才有
    client *derpclient.Client
    state  relayState     // down / dialing / up
    lastRecv time.Time
    rtt      time.Duration
    ...
}

engine.relays []*relayConn
```

- 启动时对 `derp` + `derps` 去重后的 URL 列表各建一个 relay，独立拨号、独立重连、独立 keepalive/pong；
- `pump` / `keepalive` 从 `e.client` 改为绑定各自的 `relayConn`；
- 每条 relay 的读错误只 teardown 自己，不再影响其他中继；
- **入站数据帧按 KCP conv 分流**：`frameData` 的 payload 前 4 字节就是 KCP conv，`pump` 用 `(peer, conv)` 查路由表投递到对应链路的 KCP 队列。primary 的 conv 仍是 `relayConv(pair)`，data link 的 conv 加入 relay identity；同一 peer 在同一中继上可以同时有 primary 和 data link，不冲突。
- 控制帧仍按 peer 路由；但 `handleControl` 增加 `via relayID`，因为 `ctrlLinkHello` 必须知道它从哪条中继来。
- `sendControl` 增加“经哪条 relay 发送”的入口；现有调用默认走 home relay。

### 4.2 链路模型

| 链路 | 组成 | 承载 | 何时存在 |
|------|------|------|----------|
| primary pair link（现有 `peerConn`） | pair KCP + secure(tag 0x00) + smux，可装 direct underlay | 控制面；直连；home relay 数据；TUN/`ip` link | 首次需要时（现有逻辑） |
| data link（新增 `relayLink`） | 独立 KCP(conv 含 relay id) + secure(link tag) + smux + accept loop | 仅数据 stream / 非 `ip` 的 UDP edge | 直连不可用且两端都声明 multipath 时，按需创建 |

- primary pair link 仍绑定一个 **home relay**；它的 relay underlay 可以在 home relay 故障时切到下一台中继（复用现有 underlay 交换），direct 路径不受影响。切换后 primary 与既有 data link 可能落在同一中继，靠 conv 分流共存。
- data link 每个 `(peer, relayID)` 一条，没有 direct underlay，不参与 `direct` 状态机。
- data link 由 per-peer link manager 管理：直连活着时不建；直连不可用（或 `direct:false`）时**主动建齐**（见 §4.4），而不是等某次 open 临时创建。空闲超时（默认 10 分钟无 stream，且 direct 已恢复、primary 足够）后整条拆掉，下次需要再建。
- 每条 data link 有自己的 smux accept loop；入站 stream 仍走统一的 `acceptLoop` → target/inbound queue，不需要两端协商“谁开在哪条”。

### 4.3 home relay 选举

- 两端连接全部中继后，各自拿到 relay identity 集合。
- 通过控制面（`ctrlCaps` 扩展）交换 relay identity 集合、multipath capability 和**当前 home identity**。
- 初次选举：home relay = 两端集合交集内、当前健康、identity 字典序最小的一条。
- **粘性**：当前 home 仍健康时，不因为更低 ID 的中继恢复而搬回；只有当前 home 不健康、或对端广告了一个更小的 home 时才重算/迁移。这样避免低 ID 中继抖动导致 primary 反复重建。
- home relay 故障时：primary pair link 按 identity 升序尝试剩余中继，直到 smux 会话建成；确定新 home 后重新广告。
- 若两端健康视图短暂不一致：以较小的 home identity 为准；较小的一方保持，较大的一方迁移。primary 的“失败后尝试所有中继”是最后兜底；data link 各自独立，不依赖 home。

### 4.4 调度

`OpenStream(peer)` 与 UDP link 创建时选链路：

1. primary pair link 有 live direct underlay → **只用 primary**（直连优先）；
2. 否则候选 = primary 的 relay 路径 + 所有健康 data link；
3. 选择规则：`inflight / weight` 最小，平局按加权轮询；默认 weight=1；
4. 打开失败（超时/会话已死/peer gone）→ 标记该链路 suspect，换下一条重试，最多 N 次（默认 2 次）；
5. 没有健康链路 → 返回现有错误（调用方重试）。

**就绪与等待**：直连不可用时，per-peer link manager 立即并行建立候选 data link（hello 完成才算 `up`）。`OpenStream` 在一条 data link 都未就绪时最多等待 `linkReadyWait`（默认 2s），然后回退到 primary；这样一串并发 open 不会全部先挤到 primary，验收里的“两条链路都有流量”才可复现。等待只发生在新连接，不影响已有连接。

`inflight` 以 stream/link 计数，不做实时吞吐反馈。理由：实现简单、避免测量噪声导致抖动；v1 的目标是“多条连接能分散”，不是“最优调度”。

### 4.5 控制面与 relay 集合广告

- `ctrlCaps` 负载从 1 字节扩展为 `[caps][n][32B relayID]*[32B homeID]`；旧 peer 只读 `clear[0]`，忽略尾部，安全。
- 新增能力位（不复用现有 IPv6 bit 0）：`capRelaySet`、`capMultiPath`。
- 两端在 home relay 上交换集合；集合未交集或对端无 `capMultiPath` → 退化为单中继（primary）。
- 集合或 home 变化时重新发送 `ctrlCaps`（幂等；对端按最新一次覆盖 relay 集合，home 按 §4.3 的规则收敛）。
- 控制帧可以指定从任一 relay 发出（`ctrlLinkHello` 必需）；`handleControl` 增加 `via relayID` 参数，用于路由 link hello 与未来扩展。

### 4.6 链路在线探测（link hello）

DERP 对“目的 peer 不在本中继”只丢包，不回错。因此 data link 不能“先发数据再等对端发现”，必须有一个**建链握手**：

- 新增 `ctrlLinkHello`：`[kind][linkTag 32B][keyEpoch 8B][nonce 8B]`，经目标 relay 发送；
- 发送方先建好自己的 KCP pair、secure（由 pair ECDH + linkTag 派生）和 smux 半边，但不发数据；
- 接收方从同一 relay 收到 hello 后，校验 `linkTag == 该 relay identity`、`keyEpoch` 与当前 pair 密钥代一致；然后建立自己那半边（KCP/secure/smux，角色仍按 public key 排序），**就绪后**回显 `[kind][linkTag][epoch][nonce]`；
- 发送方收到回显才把该 data link 标为 `up` 并开始发数据；超时（默认 3s）或 epoch 不符 → 该链路 `peer-absent`/`stale`，不进入调度；
- `peer-absent` 不是终态：按退避（5s/10s/30s，封顶 30s）重新 hello，relay 重连和新的 open 需求也会触发立即重试；
- 旧 peer 不认这个 kind，也不会在额外中继上出现；新端只在 `capMultiPath` + 集合交集确认后才发 hello。

### 4.7 安全与密钥

现有 `secureSession` 保留 `eph`/`peerEph`，`deriveFor` 可重算 ECDH。多中继需要把“握手”和“链路密钥”分开：

- **pair key agreement（新）**：每个 peer 一份，持有 ECDH 临时密钥、对端临时公钥、共享秘密和 `keyEpoch`；它承载 `ctrlSecure` 交换，但**不随 relay 连接或 primary 会话销毁而丢弃**。home relay 挂掉、primary 重建，pair key agreement 继续有效。
- primary link 用 transport 0x00、无 linkTag，密钥派生保持与旧 peer 兼容。
- data link 从同一个 pair 共享秘密派生：HKDF info = `"p2p-session-v1" + transport + linkTag`，`linkTag = relayID`。每条 data link 有独立 `sendKey`/`recvKey`/`nonceCtr`，且独立于 home relay 的选择——杀掉 home relay 不会让其他中继上的 data link 失效。
- 只有对端重启/身份变化（`ctrlSecure` 的 ephemeral 改变）或显式 desync 恢复才 `keyEpoch++`，并拆掉所有链路重新派生；旧 epoch 的 hello/数据被拒绝。
- primary 的 secure session 可以继续复用 pair key agreement 的派生结果；`dropRelaySecure` 的语义要改成“丢链路派生，不丢 pair 握手”。
- 加测试向量：同一 ECDH 秘密、不同 linkTag → 密钥不同；一条链路的密文不能在另一条链路解密；home relay teardown 后 data link 的密钥不变。

### 4.8 故障处理

| 事件 | 处理 |
|------|------|
| relay 连接读错误/无 pong | 只 teardown 该 relay；其 data link 全部 down；primary 若在它上面则切 home。**pair key agreement 不丢，其他 data link 不 rekey** |
| data link smux keepalive 超时 | 只杀该 data link 的 stream；标 down；不影响其他链路 |
| `PeerGone`（某中继） | 只标该 `(peer, relay)` peer-absent，杀该 data link；不动其他链路与 direct |
| direct 从坏变好 | 新连接立即回到 primary（直连优先）；已分散的旧连接留在原链路直到结束 |
| direct 从好变坏 | primary 的 relay 路径继续用；link manager 主动建 data link，新建连接开始分散 |
| home relay 挂掉 | primary 切到下一台；data link 继续用；控制面在新 home 重新广告 |
| 全部 relay 都 down | primary 退回 direct（若活着）；没有可用路径时按现有逻辑报错 |

`resetPeerSession` / `dropRelaySecure` 等现有“整 peer 重置”路径必须区分链路：data link 故障不能触发 primary 的 secure/KCP 重置，反之亦然；只有 `keyEpoch` 变化才允许跨链路重置。

### 4.9 UDP 与 TUN

- 普通 UDP dial 在创建时选一条链路，并把该链路作为它的 peer edge carrier；
- 链路挂掉时，现有 link 的 `sessionScoped` / grace / re-dial 逻辑处理重建；
- **TUN/`ip` link（`server.go` 的 `ip` tunnel）固定走 primary**，不参与多中继调度。它是 `sessionScoped`：状态注册绑在 primary 会话的 generation 上；把它放到 data link 会让 `peerSessionEvents` 与状态注册语义全部错位，而且单条 tun 属于“单流”，本就不在 v1 目标内。
- 因此 v1 的多中继吞吐收益适用于**多条 TCP tunnel**和**普通非 `ip` UDP dial**，不适用于单条 tun。
- 不为单个 UDP flow 做跨链路 striping。

### 4.10 配置

```yaml
derp: wss://relay-a.example/derp   # 兼容现有；作为列表第一项
derps:
  - wss://relay-b.example/derp
  - wss://relay-c.example/derp
```

- 有效集合 = `[derp] + derps`，按 URL 去重；连接后按 relay identity 再去重；
- 空集合 = stub 模式（现状）；
- 可选：`derpWeights`（v1 可不做，调度器默认等权）；
- 配置只在本地，不走 wire。

### 4.11 可观测性

- `Status` 增加每条 relay 的：identity、URL、连接状态、RTT、peer 是否在线、data link 状态、stream 数、字节数；
- 现有 `RelayConnected/RelayRTT` 保留为 home relay 的兼容视图；
- 日志统一带 `relay=<id>` 字段；链路建立/拆除/hello 失败/调度跳过要能单独 grep；
- `doctor` 输出每条中继一行；
- 注意：`Status` 是 `p2p` 结构，映射到 `p2p/grpc` 与 `plugin/p2p/proto`。新增字段是 proto 变更，按仓库约定先改 `plugin/` 契约、打 tag，再升 `p2p` 的依赖，最后 `GOWORK=off` 验证。

### 4.12 兼容与灰度

- 单中继配置、旧 peer：行为与现在完全一致；
- 新 peer + 旧 peer：旧 peer 不广告 `capMultiPath`，新 peer 只使用 primary，不建 data link；
- 新 peer + 新 peer：先交换 relay 集合，再按需建 data link；
- 两端集合不一致时：交集为空 → 只保留 primary；交集非空但 home 不同 → 以较小的 home 为准收敛，primary 的“尝试所有中继”兜底；
- wire 变更是**增量**的：新增 `ctrlLinkHello` kind、`ctrlCaps` 尾部字段；旧代码忽略未知 kind / 尾部字节，单中继行为不变。

## 5. 实施分期

### Phase 1：多 relay 连接、健康与帧分流

- `Config.Derps`、relay registry、独立 pump/keepalive/重连；
- `sendControl`/`handleControl` 带 relay 上下文；
- 入站数据帧按 `(peer, KCP conv)` 分流（本阶段先让单链路也能走通路由表）；
- 每条 relay 的状态、日志、`Status` 内部字段；
- 测试：两继电器同时在线、单台故障不影响另一台、拨号失败重试、conv 路由。

### Phase 2：集合广告、home 选举与 link hello

- `ctrlCaps` 扩展 + 能力位 + 当前 home；
- 粘性 home relay 选举与重新广告；
- `ctrlLinkHello` 建链握手（epoch、就绪后再回显、退避重试）；
- 测试：集合交集、旧 peer 降级、hello 超时/重试、home 收敛。

### Phase 3：pair 密钥与 data link 调度

- pair key agreement 从 relay 生命周期解耦；`keyEpoch` 与 linkTag 派生；
- `relayLink`（KCP conv 含 relayID、secure linkTag、smux、accept loop）；
- per-peer link manager：直连不可用时主动建齐并等待就绪；
- `OpenStream` / 普通 UDP 的链路选择与失败重试；TUN/`ip` 固定 primary；
- direct-first：direct live 时不建 data link；direct 消失后建；
- 空闲拆除；
- 测试：两条链路都有流量、单链路故障只影响其 stream、新连接绕开、direct 优先、home relay 故障后其他 data link 不 rekey。

### Phase 4：观测与集成

- `Status`/proto/doctor/日志；
- `cmd/p2p` 配置与 flag；wisper `P2P.Derp` → 列表（API/UI 另行安排）；
- e2e：多 derper 容器、吞吐与故障场景；
- 文档与迁移说明。

## 6. 验收标准

1. **聚合**：`direct:false`、2 条中继、8 条并发 TCP 流；两条 relay 的字节计数都非零，总吞吐 ≥ 单中继基线的 1.5 倍（在本地/远端 access link 未饱和的前提下；测试用固定阈值并记录基线）。
2. **故障隔离**：跑流中杀掉 relay B；B 上的连接断开，A 上的连接不中断；5s 内新连接能在 A 上成功。B 是 home 时同样成立：pair key agreement 不随 home teardown 丢弃，A 上的 data link 不 rekey。
3. **直连优先**：direct live 时新连接全部走 direct；杀掉所有 relay 不影响已在 direct 上的连接；direct 消失后新连接开始分散到 relay。
4. **旧 peer**：新 peer + 旧 peer、同一 primary relay，行为与单中继完全一致，且不尝试 data link。
5. **安全**：两条链路密钥不同；同一明文在 link A 的密文不能在 link B 解开；nonce 序列独立。
6. **工程**：`GOWORK=off` 各模块构建通过；`go test -race` 干净。

## 7. 风险与权衡

- **DERP 队列**：每条 relay 每条连接仍有有界发送队列；链路越多，单链路排队概率越低，但总连接数上升，relay 侧负载增加。
- **内存/CPU**：每 peer 最多 N 条 KCP+smux；直连不可用时主动建齐，空闲 + direct 恢复后拆除，限制峰值。
- **调度不完美**：least-in-flight 对长连接公平，但对“少量大流 + 多条小流”可能不均；v1 接受，后续可加字节级权重。
- **home relay 分裂**：两端健康视图不一致时可能短时间各选不同 relay；以较小 home 收敛 + primary 尝试所有中继 + 重连兜底，代价是秒级中断。
- **安全代码**：pair key agreement 从 relay 生命周期解耦、HKDF linkTag 都属于安全敏感改动；必须有 epoch、测试向量与 review。
- **状态/proto**：新增字段需要跨 `plugin`/`p2p` 模块升级，灰度顺序不能反。
- **与现有迁移模型的关系**：primary 的单 KCP direct↔relay 迁移保持不变；data link 不参与迁移，故障即断（已接受）。

## 8. 实现者需要落定的细节（默认值，可在实现中调整）

- data link 空闲拆除：10 分钟；home relay 探测超时：3s；link hello 超时：3s；打开失败重试次数：2；link 就绪等待：2s。
- `peer-absent` 退避：5s / 10s / 30s（封顶 30s），relay 重连或新 open 需求可提前触发。
- 调度默认等权；v1 不做实时吞吐反馈。
- `ctrlCaps` 扩展的 relay 数量上限（例如 16），超出忽略。
- relay identity 冲突（两个 URL 指向同一 server key）按一条链路处理，保留先配置的 URL 作为显示名。
- 旧 peer 的判定完全依赖 `capMultiPath`；不根据版本号猜测。
- pair key agreement 的 `keyEpoch` 只需进程内 + 对端一致，不持久化；进程重启视为新 epoch。
