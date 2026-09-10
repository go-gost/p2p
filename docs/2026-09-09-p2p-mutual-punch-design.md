# 互撞拨号打洞（Mutual Simultaneous Punch）设计

日期：2026-09-09 · 状态：implemented（2026-09-09）
　（v2：echo 判据、收敛闭环、dummyProbe 定删、测试补强；v3：kcp-go 源码深读 R1–R8、NewConn4 修正、timeouts 配套）
模块：`p2p/`（`direct.go` 为主，engine/server 不动）

## Context

k3s pod（server 角色）对 client（NAT 内网）的场景暴露了现打洞机制的**方向不对称病根**：

现在 `punch()` 按 pubkey 序分角色：client 角色**单边** `NewConn3` 拨一个候选并 prime，
server 角色只 dummyProbe + `ServeConn` accept + 手工 echo。一旦「能通的那一侧」不是 client
拨的那个方向（典型：pod 入站 UDP 需要 conntrack-assist——pod 先发过到 client 的流才建出可回程
条目），单边赌方向就失败。早前评估过「角色翻转重试」，但它仍是**换一边单边猜**，不解决根基。

**结论（spike 已验证）**：改为**互撞拨号**——双方各自对对方候选 `NewConn3` 一个同 conv 会话，
删掉「谁 dial、谁 accept」的角色划分。KCP 两端同 conv 是纯对称协议，互撞自动合并成一个会话
（临时 spike 测试两测全过、`-race` 干净：纯双向应用流量 + smux 双开流；已验证后删除，升格版
测试方案见「测试」节）。这同时回答「角色翻转怎么做最可靠」：**不再需要翻转**——双方都 dial，
不存在赌方向的决策点。

## 目标 / 非目标

- 打洞成功率对「哪侧先能通」不敏感：只要两个方向最终都建立（含 k3s conntrack-assist 的
  时序情形），punch 就成功。
- 保持既有约束：每 UDP socket **一个** KCP 会话（kcp-go 每会话一个 readLoop，双会话抢包——
  历史 bug 0e8d810）；conv 仍确定性派生；smux 会话角色仍按 key 序且**与谁拨号解耦**。
- 非目标：穿透 restricted/symmetric NAT（对端到我方映射 ≠ 其对 STUN 映射 → 仍回落 relay，
  与今日一致，属打洞固有边界）。不保证与旧版本二进制混合部署（控制面/候选帧未变，实测一般
  可互操作，但不作为承诺）。

## 数据流（punch 逐段）

1. **候选广播**（同今日）：绑 egress-IP UDP socket → `stun.Lookup`（同一 socket）→ 经 relay
   control `[0x00][0x02][sealed]` 互换候选 `[local, public]`。
2. **dial 目标选择**（两侧独立执行同一规则，保证对称；仍**每侧单候选**，kcp readLoop 约束不变）：
   hairpin 检测同今日——peerAddrs>1 且己方 public IP == 对方 public IP → 拨 peerAddrs[0]（本地），
   否则拨 peerAddrs[last]（public）。
3. **互撞拨号**：双方各自 `kcp.NewConn3(conv, dialAddr, nil, 0, 0, ownSocket)`。每端一个会话
   一个 readLoop，无抢包。conv = sha256(排序双 key) 前 4B（不变）。
4. **对称 echo 握手**（primeKCP 的去中心化版）：会话建成后双方执行同一四步——①写自己的
   1 字节 token T；②读对端 token T'；③回写 T'（echo）；④读自己 token 的 echo T''，要求 T''==T
   （deadline ≈5s）。**成功判据 = 自己的 token 完整往返（own→peer→own）**，与今日 primeKCP
   证明强度一致：任一侧只在「自己发出的字节被对端回送」后才认直连可用，**杜绝只收到对端 token
   就误判直连的假直连**（单方向永久不通时两侧都判败 → 干净回落 relay）。
   kcp 对未 ack 字节持续重传，窗口内多处重传足以覆盖 k3s conntrack 的「先单向、后反向」建流
   时序（典型成因：pod 先发出到 client 的包才建出节点上可回程的 conntrack 条目，之后反向放行）。
5. **smux**：双方 `smux.Client/Server` 按 key 序（与拨号无关，spike 已证），各自 keepalive +
   acceptLoop（目标 bridging 不变）。
6. **失效恢复**：双方都是 dialer → 会话死（acceptLoop 退出 markDead / OpenStream 直连检查 /
   onCandidates 收新候选）后**任一侧**可独立重拨重打。今日「仅 opener 感知死亡」的单点与
   missed-PeerGone 兜底（onCandidates 拆陈旧 directUp）逻辑得以简化保留。

## 变更点

`p2p/direct.go` 内 punch 路径重写：

- `punch()`：删角色分支；删 server 侧 `ServeConn`+`kcpAccept`+`AcceptKCP`；统一走上述 2–4。
- `primeKCP` → `seedHandshake`：上述对称四步（写 token / 读对端 / 回 echo / 读自身 echo），
  超时判败并 teardown socket（re-punch 新 socket）；**成功后必须清 deadline**（历史 a3d31f1
  同型：残留 deadline 会杀死会话）。
- **socket 所有权**：改用 `NewConn4(..., ownConn=true, socket)`（见「依赖升级注记」末条）——
  会话死亡自动关 socket、readLoop 随之退出；`dc` 的显式 close 变为幂等兜底。此前的
  `keepSocket` 手工记账可删除。
- `dummyProbe`：**删除**。互撞下双方都在向对端发送真实 KCP 流量，NAT/conntrack 映射由互拨
  流量自身建立，无需独立探测。
- `markDead`/`session()`/`onCandidates`/backoff：保留，语义天然对称化。
- `peerAddr` 日志：取会话 remote（dialed 目标；源过滤保证其 == 对端实际发包源）；日志 `role`
  字段（client/server）在新机制下失去意义，随之移除。
- **收敛闭环（不变式）**：每次 punch 起始必广播候选 → 对端 `onCandidates` 拆陈旧会话并就地
  对齐重打。候选每次 punch 只发一次，故陈旧候选至多引发一轮额外收敛、不会无限抖动；重打若
  变更源端口导致对端旧会话源过滤拒收，同样靠这一闭环重建。

互撞机制本身对 engine.go / server.go / derpclient.go / 控制面帧：**零改动**（配套的
`timeouts:` 会触到 engine.go/config.go，见下节）。

## 配套变更：时间参数可配置（`timeouts:`，已定 scope）

互撞实现与 k3s 实测都标注「窗口以实测为准」；写死参数意味着每次调参都要重编译。经评估
**只开放部署相关的小集合**——内部机制参数（stream/gone/dial/bridge 超时等）保持写死：
它们没有部署差异，开放只会掩盖 bug。

```yaml
timeouts:
  punchWait: 5s       # OpenStream 等待打洞上限（首连延迟 ↔ 成功率）
  punch: 10s          # 打洞全程窗口（候选等待/prime）
  seed: 5s            # 对称 echo 握手窗口（互撞新增）
  backoff: 30s        # 打洞失败重试间隔
  derpKeepAlive: 30s  # DERP 连接保活（须低于部署的 CDN/proxy 空闲超时）
  smux:
    interval: 10s     # smux keepalive 间隔（relay + direct 两处统一）
    timeout: 30s      # smux keepalive 超时
```

**规则**
- 仅 config（`-C`）可设，不加 flag；未设即现默认值（零值跳过赋值）。
- 启动时校验，非法即退出：设值必须 > 0；且 **`smux.timeout ≥ 2 × smux.interval`**——
  smux 自身 `VerifyConfig` 只要求 `timeout ≥ interval`，而两次咬我们的恰是「相等」
  （空闲会话 10s 自杀 / relay NOP 停流致 PeerGone 丢失）；2× 是「至少撑过一次 NOP 丢失」下限。
- 不开放（保持写死）：`streamOpenTimeout` / `goneOpenTimeout` / `goneProbeTimeout` /
  `dialTimeout` / reconnect 5s ticker / bridge 5s / stun 3s。`candidateTimeout`、`stunTimeout`
  保持包级 var（仅供测试缩短），不进 config。

**落点**
- `config.go`：`Timeouts *TimeoutsConfig`（`time.Duration` 字段；goccy 原生支持 `"5s"`，
  与 x/ 同款用法）。
- `engine.go`：`keepAlivePeriod` const→var；relay 与 direct 两处硬编码的 smux `10s/30s`
  抽成包级 var（`smuxKeepAliveInterval/Timeout`），顺带消除重复。
- `direct.go`：punch 组已是 var；新增 `seedTimeout` var。
- `main.go`：config 加载后 `applyTimeouts`（校验 + 赋值），非法 `os.Exit(1)`。
- 测试：`TestApplyTimeouts`——零值跳过、负值拒绝、`timeout < 2×interval` 拒绝、合法生效。

## 测试

- 将 spike 两测升格进 `direct_test.go`：互撞 NewConn3 合并 + 其上 smux 双向流（回归，防 kcp-go
  行为变更）。
- 重跑既有 direct 测试（round-trip / survives-punch-timeout / fallback-to-relay /
  local-candidate / stun-unreachable / repunch-after-death / repunch-after-missed-gone），
  `punch()` 重写后必须全绿。
- 新增：`seedHandshake` 单测——token 完整往返成功；「只收到对端 token 但自己 echo 不回」判败
  （假直连回归）；超时判败回落 relay。
- 新增（机制级回归，本方案核心价值的锁）：`TestMutualNewConn3Merge` + `TestMutualKCPWithSmux`
  （已实现）——互撞合并与其上 smux 双向流的 kcp 层回归。
- 半通路径由 `TestSeedHandshake` 覆盖（对端 token 到达但自身 echo 不回 → 判败）；完整
  conntrack 时序在 k3s 实测验证——进程内 UDP shim 需要生产代码加测试缝，不做。
- 互撞成功后 kill relay 数据帧 → 直连仍通（沿用既有模式）。
- 端到端：derper + 两 host 既有拓扑；k3s pod 场景按部署实测。

## 风险 / 遗留

- 若对端实际发包源 ≠ 其公网候选（非 cone NAT / 中间盒改写），源过滤会拒收 → echo 超时判败 →
  relay。与今日边界一致。hairpin 判定是对同一对 public IP 的比较，两侧结果必然一致，无分歧风险。
- echo 判据要求完整往返；conntrack-assist 反向建立若 >5s 会误判（双方都会判败 → relay，安全但
  降级）。窗口以实测为准，保留常量便于调。**深层读源码后已量化：RTO 初值 200ms、每次重传
  累计退避（200/400/600…），5s 窗口内约 6-7 次重传——节奏与窗口匹配，暂不需要 `SetNoDelay`**。
- k3s「client 能否到 nodeIP:port」的入站模型仍未实测——若路由器无任何入站路径，任何打洞
  （含本方案）都不可达，只剩 relay。建议实现后配合一次诊断跑。
- 每次重打洞重新 `ListenUDP`，源端口变化会丢弃旧 NAT/conntrack 映射（对 k3s SNAT 亲和性不利，
  #51 同型）。若实测受影响，改为固定本地端口 + SO_REUSEADDR 复用。

## 外部参考：kcp-go issues 调研（2026-09-09）

逐条对照本设计（listen 均指 kcp `ServeConn`/`AcceptKCP` 路径）：

| Issue | 内容 | 对本设计的印证 |
|---|---|---|
| **#252**（closed） | 打洞后两端 `NewConn2` 互拨，字节都到了（`WriteTo`/`ReadFrom` 有数据）但 KCP 层读不出 | `NewConn2` **每端随机 conv** → conv 不匹配全丢。**确定性共享 conv 是互撞的硬前提**（我们的 sha256(排序双 key) 恰好满足） |
| **#154**（closed） | 打洞后双内网互连，KCP 收数几包后停，但裸 `UdpConn.Read` 仍见包 | 双重印证：① conv 随机不匹配；② 同一 socket 上应用自读 + KCP readLoop → **双读者抢包**。我们严守「一 socket 一消费者」 |
| **#54**（closed，Syncthing AudriusButkevicius） | KCP **无控制消息**：一端重启后，对端旧会话的包被重启侧当成「新连接」，两端都变 listen-mode，双双 `smux.Accept`，幽灵会话永久僵死（有 workaround commit） | 我们**打洞路径完全不用 Listener**（双端均 client-role），配合确定性 conv，从根上绕开「对称 listen 僵死」；残留的「对方旧会话发往旧源地址」由 `onCandidates` 拆陈旧 + 每次重打新 socket 兜底 |
| **#223**（open）、**#150**（open）、**#54** | Listener 按 `sessions[addr.String()]` 键会话（v5.6.72 仍如此，见 packetInput）；换网/VPN 换源 IP → 判新会话；conv 冲突仅靠 sn==0 reset 包收敛 | 佐证避开 Listener 的正确性；client-role 源过滤 = dialed remote，换网后旧会话自然死、重打新会话 |
| **#51/#36/#24**（closed） | 绑定本地源端口 / 传 `net.PacketConn` 的需求 | 我们绑 egress-IP socket、自带 PacketConn，已满足；**重打新 socket 源端口会变**——对 k3s SNAT conntrack 亲和性不利，列入风险（未来可尝试固定本地端口复用） |
| **#341 / #152 / #155** | Listener 侧对同一 addr 握手重传去重、conv 冲突取 sn==0 建新会话 | 与我们无关（无 Listener），记录备忘 |

## 依赖升级注记（2026-09-09，kcp-go v5.6.72）

升级到 v5.6.72（+smux v1.5.57）后全量 `-race` 25 测通过，无回归。评估 NewConn4
（`NewConn4(conv, raddr, block, dsh, psh, ownConn, conn)`）：

- v5.6.72 的 `NewConn3` 已等价 `ownConn=false`（会话 `Close()` 不再关闭传入 socket）——较旧版
  行为变更，与本模块自管 socket（`keepSocket`+defer）语义一致，反而更干净。
- readLoop 新增 `isClosed` 检查（linux 与 generic 路径均核过：读到事件后才检查，阻塞读仍靠
  **socket 关闭**解阻塞）——即重打/teardown 时仍必须关 socket 才能杀 readLoop，不可只 Close 会话。
  client-role 会话仍**各自** `go readLoop()`——「一 socket 一 client 会话 / 单候选拨号」约束未松动。
- 源过滤从旧版「锁定首见源」改为**严格等于 dialed remote**：互撞拨号必须拨「对端真实发包源」
  的结论不变（cone NAT 下 = STUN public），本设计不受影响。
- **结论（2026-09-09 深读修正）**：NewConn3 在 v5.6.72 已是 `ownConn=false`——会话 `Close()`
  不再关 socket，而 smux 会话死亡 → conn.Close → **socket 仍在、readLoop 仍阻塞**，仅靠
  `dc` 显式关 socket 兜底（漏一处就泄漏 fd+goroutine）。**改用
  `NewConn4(..., ownConn=true, socket)` 可恢复「Close→关 socket→readLoop 退出」的自动闭环**，
  把防泄漏从「靠纪律」变成「靠类型」——这是实打实的增益，不是可读性优化（初评有误，已修正）。

## kcp-go v5.6.72 源码深读：风险清单（2026-09-09）

按对本设计的影响排序（均已核对源码，行号：v5.6.72）：

| # | 级别 | 事实 | 对设计的影响 |
|---|---|---|---|
| R1 | **高** | `kcp.state = 0xFFFFFFFF`（死链标志）只在 flush 里写（kcp.go:943），**全库无任何读取**——kcp 不会因死链自毁；重传持续且累计退避（`segment.rto += rx_rto`，200/400/600…，20 次 ≈42s 累计）| **任何半死会话的唯一发现者是 smux keepalive**（10s NOP / 30s 超时判死）。这就是 KeepAliveTimeout 必须 > interval 的深层原因：两者是一体的，调参不能拆开。seed 假死兜底与 OpenedStream 失败也都依赖它 |
| R2 | **高** | v5.6.72 `NewConn3` = `ownConn=false`（sess.go:335-367）：`Close()` 不关传入 socket；smux 死亡 → `conn.Close()` → socket 存活、readLoop 继续阻塞在 ReadBatch | 每条会话死亡路径都显式关 socket，或直接换 `NewConn4(ownConn=true)`（见「依赖升级注记」）。漏关 = 泄漏 fd+goroutine，且同 socket 重建会话会双 readLoop 抢包（0e8d810 复现土壤——本设计每轮新 socket 已规避抢包，但仍须防泄漏） |
| R3 | 中 | 严格源过滤：linux（readloop_linux.go:49-93）与 generic（readloop.go:46-82）均从 `s.remote` 初始化；`sameUDPAddr` = port+zone+`IP.Equal`（::ffff:a.b.c.d 与 a.b.c.d 视为相等）| 「必须拨对端真实发包源」结论不变；**v4-mapped 表示差异不会误杀**（与 STUN 的 v4-mapped 修复配合良好） |
| R4 | 中 | 输出回调（sess.go:227-245）：chPostProcessing（2048 深）满时**静默丢段**（注释：KCP 会重传）| 吞吐行为非正确性（丢段由 RTO 兜底）；我们载荷极小，无影响。记录备用 |
| R5 | 中 | `Close()` 先 `close(die)` 再 `flush(FULL)`；输出回调 select 中 `<-die` 与入队同时就绪 → **随机丢弃**部分尾段（且不回池，有界）| 干净关闭的最后一个 FIN/段可能丢 → 对端靠 R1 的 smux 超时发现。对隧道语义无害（关闭即断），记录 |
| R6 | 低 | 定时器重构为全局 `SystemTimedSched`（timedsched.go）：N=NumCPU worker + 每 worker 本地堆，`execute()` = `sess.update`（持 `s.mu` 跑 flush）| 单会话慢 flush 会延迟同 worker 其他会话的定时；本 host 会话数是个位数，无风险。记录 |
| R7 | 低 | RTO 量化：初值 200ms（IKCP_RTO_DEF）、min 100ms、max 60s；normal 模式重传累计退避 | 5s seed 窗口 ≈ 6-7 次重传（0/.2/.6/1.2/2.0/3.0/4.2s）——与 conntrack 打开时序匹配，**不需要 SetNoDelay** |
| R8 | 低 | 段缓冲走 `defaultBufferPool`；R4/R5 的丢段路径回收不完整但有界 | 池泄漏有界，可接受。记录 |

**正面结论**：窗口 WND_SND/WND_RCV=32 段（≈45KB/会话方向）；`update()` 自适应 flush 间隔
（`SystemTimedSched` 自重排）；均与本设计兼容，无需调参。
