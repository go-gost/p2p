# p2p 路径迁移：单一 KCP 会话 + relay/direct 双 underlay（设计）

- 日期：2026-10-05
- 状态：已评审；2026-10-06 复审修订（H1–H5、M1–M3，见「复审修订」）；下一步 writing-plans
- 关联：`docs/2026-10-04-p2p-relay-kcp-reliability-design.md`（KCP over DERP 基线）
- 关联：`docs/2026-09-30-p2p-e2e-encryption-design.md`（secure 层）
- 证据：`internal/host/spike_kcpmigrate_test.go`（throwaway spike，保留作可复现证据）
- 记忆：`.memory/notes/p2p-kcp-session-migration.md`

## 背景与证据

现状：每个 peer 有**两条独立 KCP 会话**：

- relay pair：`relayKCPPair.session()` 用 `kcp.NewConn4(relayConv(...), dummyAddr{}, nil, 0, 0, false, p)`（`relaykcp.go:199`），secure tag `0x00`。
- direct：`kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, f.sock)`（`direct.go:1222`），secure tag `0x01`。

`OpenStream` 在打开流时二选一（`engine.go:823-903`），且**选择对该流终身冻结**：direct 起来之前打开的流永远留在 relay。README 也如此描述。对 datagram/tun link 尤其致命——一个 link 的 local 流与 edge 流都绑在打开时的平面上。

调研与 spike 结论（详见记忆笔记）：

1. kcp-go 无迁移 API，但**不需要**：调用方自持的 `net.PacketConn` 完全控制底层。
2. 迁移应放在 **KCP 层**：KCP 已具备 `snd_buf`/序号/ACK/RTO；换底层路径后它在新路径重传未确认段、按序号去重，字节流无损切换，上层 smux 无感。
3. Spike 实证（`spike_kcpmigrate_test.go`，KCP→smux 全链路，8 MiB + 4 MiB，切换点注入 200 ms 黑洞 + 乱序 + 重复，`-race -count=3` 全绿）：
   - 单条 `ownConn=false` KCP 会话在调用方 `PacketConn` 换发送路径下无损迁移；
   - **双读两条路径是承重的**（不双读时会话饿死）；
   - kcp-go `defaultReadLoop` 锁定源地址：统一 `PacketConn` 必须对两条路径返回同一稳定 `dummyAddr{}`，否则包被静默丢弃。

## 目标

- 每个 peer **一条 KCP 会话**（conv = `relayConv`，secure tag `0x00`）承载该 peer 的所有流（字节流 + datagram link）。
- 该会话挂 **relay(DERP)** 与 **direct(UDP)** 两条 underlay；**双读**，发送走 preferred。
- preferred = 最近收到入站包的那条 underlay；direct 无近期入站则回落 relay。
- direct 打通后，**已打开的流自动迁到 direct**；direct 掉线自动回落 relay。切换期的不丢/不重/不乱序由 KCP ARQ 保证，上层无感。
- **pair 的存活与 relay 解耦**：direct 活跃时，relay 抖动不得拆掉 direct（见「pair 生命周期」）。
- 保持端到端加密：secure **协议机制**不变，direct 只在其下搬字节。

## 非目标

- 不改 smux、link/handler 逻辑。
- 不做多路径并发/聚合（不是 MPTCP：同一时刻只从一条 underlay 发送）。
- 不做混合版本兼容：假定两端同时升级，线格式可自由变更（与 2026-10-04 设计同）。
- 不改 derper。
- 不引入 kcp-go 的 block 加密 / FEC（维持 `block=nil`、shards 0,0）；direct 入站按对端地址过滤，与现状安全姿态一致。
- 不新增「direct 温备」态（`direct` 一旦不被优先即摘除并 re-punch，见组件 5 H3）。

## 架构

```
                 ┌──────────── pair (per peer) ────────────┐
 relay(DERP) ──▶ │ relayUnderlay ─┐                        │
                 │                ├─ fan-in ─▶ KCP 会话 ─▶ secure(0x00) ─▶ smux ─▶ link/handler
 direct(UDP) ──▶ │ directUnderlay ┘      (conv=relayConv)  │
                 └───────────────┬─────────────────────────┘
                                 │ send: preferred
                                 └─▶ relayUnderlay / directUnderlay
```

与原设计的差异：原 `relayKCPPair` 的 `ep` 单端点（`relaykcp.go:220-233`、`:338-389`）泛化为 N 条 underlay；relay 与 direct 互为 underlay，不再各自建 KCP/secure/smux。

## 组件

### 1. `pairUnderlay`（新接口）

```go
type pairUnderlay interface {
    name() string                    // "relay" | "direct"
    readFrom(p []byte) (int, error)  // 只返回字节；地址在 pair 边界归一为 dummyAddr{}
    writeTo(p []byte) (int, error)
    close() error
    lastRecv() time.Time
}
```

- **地址归一**：underlay 不向外暴露地址；pair 的 `net.PacketConn.ReadFrom` 统一返回 **零值 `dummyAddr{}`**（`String()=="derp"`）。必须与 `kcp.NewConn4` 时传入的 `remote` 一致（现状 `relaykcp.go:199` 传的正是 `dummyAddr{}`）；若返回 `dummyAddr{peer}`（`String()=="derp:<key>"`）会与 readLoop 锁定的 `srcStr` 不匹配而**静默丢弃所有包**（spike 结论 3）。
- **入站时间**：underlay 成功读到一个数据报时更新 `lastRecv`（原子），供 preferred 选择与 direct 存活判定。

### 2. relay underlay

- 复用现有 `relayPacketConn` / `peerConn` 与 `register(pc)` 的端点替换语义（`relaykcp.go:220-233`），把「当前 ep」封装成一条 underlay。
- 端点替换（relay 重连后重建适配器）只影响 relay underlay，不影响 direct underlay。**注意**：这只覆盖「干净替换」（`register`）；relay **链路丢失**的现有策略会 `pair.shutdown()`，见「pair 生命周期」一节，必须按 direct 存活条件化。
- 读循环保持现有「无端点则等、`io.EOF` 保留给 pair 结束」的契约（`relaykcp.go:338-366`）。

### 3. direct underlay（新）

- 持有 `*net.UDPConn`（打洞胜出的 `f.sock`，`net.ListenUDP`，非连接）与对端 `netip.AddrPort`。
- `readFrom`：`ReadFromUDP`；**丢弃来源地址 ≠ 对端地址的包**（kcp-go 的源地址锁因 `dummyAddr{}` 失效，必须自建；强度等价现状）。
- **seed magic 包必须回 echo，不能丢弃**：注册后若对端仍在 seed（或对本人 token 的 echo 丢失后重传），丢弃会让对端永远收不到 echo → **单边 punch 成功**（H2）。因此 underlay 对 seed magic 包一律按迟到 responder 回 echo；magic 同时用于区分 seed 与 KCP，避免二者抢同一 socket 时污染会话。
- `writeTo`：`WriteToUDP` 到对端地址；错误吞掉（与 relay 一致——kcp-go 把 `WriteTo` 错误当永久致命，见 `relaykcp.go:368-389`）。
- `close`：关 socket、置 down。

### 4. fan-in 与 preferred

- pair 持有缓冲 `recv chan []byte`；每条 underlay 一个 goroutine 循环 `readFrom → recv`。
- pair 的 `ReadFrom`：等待 `recv`，返回 `dummyAddr{}`；pair 关闭时返回 `io.EOF`。
- pair 的 `WriteTo`：`preferred()` 选 underlay 后写；按 underlay 计数 `bytesSent`。
- `preferred()`：`direct` 已注册且 `now - direct.lastRecv < underlayIdle` → direct，否则 relay。
- `underlayIdle`：`2 × smuxKeepAliveInterval`（3 s）= **6 s**，恒 `< smuxKeepAliveTimeout`（15 s）。窗口须大于「保证有入站流量的周期」以避免误判静默，且显著小于 smux timeout 以便在会话整体死亡前回落。**流量保证**：smux 收到 NOP 不回（`direct.go:61-67`），所以一个方向是 NOP（发送方→对端），反方向是该 NOP 触发的 **KCP ACK**（对端按其 preferred 发回）；二者合起来保证每个 keepalive 周期两个方向都有入站包。

### 5. direct 存活 / 回落 / re-punch

- 一个 watchdog 在 `direct != nil && now - lastRecv > underlayIdle` 时判定 direct 死：
  1. unregister direct underlay（关 socket、从 pair 摘除）；
  2. preferred 自动回到 relay（选择规则天然如此）；
  3. 触发既有 re-punch（`directConn.start()`）。
- 注册 direct 时把 `lastRecv` 置为现在，避免刚注册即被误判。
- 无数据丢失：切换窗口内 KCP 在 relay 上重传/重发；最多一个窗口的 ACK 停顿。
- 语义映射：`registerDirectUnderlay` ≈ 原 `markUp`（`direct.go:760`，新增对 pair 的注册调用）；`underlayDead` ≈ 原 `markDead`（`direct.go:797`）。
- **无「温备」态（H3，明确为设计意图）**：preferred 与 watchdog 是同一条件的互补，「direct 已注册但走 relay」不存在稳定态；direct 一旦 6 s 无入站即被摘除并 re-punch。健康 direct 不会触发（双向 3 s 保活保证新鲜），只有真受损才会。**代价**：边际路径会 direct↔relay 抖动，且休眠 direct 无法廉价复探（KCP ACK 走对方 preferred），只能靠 re-punch 复活——因此对「起来后很快又死」的 direct 必须加大 re-punch backoff（滞回），避免抖动风暴。
- **watchdog 回调不得自等待（H4）**：`onDirectIdle` 由 direct pump goroutine 调用；`clearDirectUnderlay` 不得同步 join 该 pump（否则自锁）。回调在独立 goroutine，或 clear 只发 stop 不 join；pump 阻塞在 `recv<-` 时必须同时 select stop。

### 6. punch 改造（保留绝大部分）

**保留**：STUN 探测（`direct.go:1443`、`:1511`）、candidates 交换、`fams` 与 v4/v6 顺序、`punch()` / `backoff()` / `retry()`、`onCandidates`。

**替换**（`direct.go:1202-1290` 的循环体）：

- 移除 `kcp.NewConn4(dc.conv(), ...)`、`dc.secure.settled()` 门、`dc.secure.conn()`、`faultConn`、`directSmuxConfig`、smux 建会话、`acceptLoop(sess, "direct")`。
- 新增 `seedHandshakeUDP(sock, peerUDPAddr, timeout)`：raw UDP 上做与 `seedHandshake`（`direct.go:1322`）同语义的 own→peer→own 往返（带 token；UDP 需按 ~200 ms 显式重试，以覆盖「对端首包后才开的 NAT 映射」）。带小 magic 前缀便于区分。
- seed 成功后：`e.registerDirectUnderlay(peer, sock, dial)` —— 把 socket 交给 pair 的 direct underlay。
- seed 的迟到响应由 direct underlay 的 echo 兜底（见组件 3 H2），保证不会单边成功。
- 胜出 family 的 socket 归 direct underlay；未用 family 关闭。

**为什么不用临时 KCP 会话做 seed**：kcp-go 的 readLoop 阻塞在 `ReadFrom` 上，`Close()`（`ownConn=false`）无法打断它，会与 pair 争抢同一 socket 的读循环；raw UDP seed 完全避开这个竞态。

### 7. secure 层（协议机制不动，只撤一个平面）

- secure 层的**协议机制不动**：会话结构、HKDF、tag `0x00/0x01` 定义（`engine.go:966/974`、`secure.go:60-63`）保持原样，pair 只用 `secureTransportRelay`。
- 仅移除 direct 平面的**构造点与消费者**：`directConn.secure`（`direct.go:237`）、`rekeyIfUsed`（`direct.go:1085`）、`dc.secure.conn()`（`direct.go:1240`）、`handleControl` 中 direct 分支（`engine.go:1446-1487` 的 `secureTransportDirect` 派发）、`resetDirectSession`（`engine.go:1544`）的 secure 关联。
- 「强制加密」由 pair 的 relay secure 满足；direct 仅搬字节，无需单独协商。
- **唯一触碰 secure 生命周期的地方**：relay 链路丢失时「何时丢弃/重置 secure」的条件化（见「pair 生命周期」H1）。除该触发条件外，不改 secure 任何既有逻辑，避开 secure-poison 历史坑（`[[p2p-relay-rebuild-secure-poison]]`）。

### 8. OpenStream / acceptLoop 简化

- `OpenStream`（`engine.go:823-903`）：删除 direct / punch 两个分支，只 `pc.ensureSession` + `openStream`；返回 `openedStream{transport: e.pairPath(peer)}`（当前 preferred 的信息标签）。
- 打洞仍由 `maybeStartDirect`（`direct.go:270`）从 pump 触发；可在 `OpenStream` 里顺便调用一次（非阻塞、幂等），保持 eager 行为。
- `acceptLoop`（`engine.go:1643`）：每个 peer 只起一次（pair 会话上），`transport` 标签改为动态（当前 preferred）。

### 9. keepalive

- pair 的 smux 用 `smuxKeepAliveInterval = 3s` / `smuxKeepAliveTimeout = 15s`（`engine.go:683-684`）。
- 删除 `directSmuxConfig`（`direct.go:1539`）与其调用；`capsTightKeepalive` 不再被消费。

### 10. stats / doctor / faults

- `relayKCPPair.snapshot`（`relaykcp.go:287`）增加：当前 preferred、每条 underlay 的 bytes / recv-at、direct 存活。
- doctor / status 的 relay/direct 展示改为「pair 当前路径 + underlay 健康」；`transport` 语义从「流终身平面」变为「pair 当前路径」（M1），消费方需同步。
- faults：数据故障过去注入在 direct underlay（`faultConn`）；现在挂在 pair 的 `WriteTo`（或 per-underlay write），并支持 **per-path mute**（只静音 direct）以覆盖「direct 死、relay 恢复」；控制故障仍走 `sendControl`。`docs/2026-09-30-p2p-fault-injection-plan.md` 的用例需相应改造。

### 11. KCP 调优（H5）

- 现状：direct 会话（`direct.go:1222`）未设 `SetNoDelay/SetMtu/SetWindowSize`，用 kcp-go 默认（snd/rcv wnd `32`、拥塞控制**开**、interval 40 ms）；relay pair 用 `SetNoDelay(1,10,2,1)`（interval 10 ms、**nc=1 关拥塞控制**）+ `SetWindowSize(256,256)`（`relaykcp.go:207-209`）。
- 统一后 direct 继承 pair 的调优：窗口 32→256 是提升；但 **nc=1 用在公网 direct 上是行为变化**——relay 的「丢包=有界队列溢出」理由不适用于公网拥塞路径。
- 决定：preferred 切到 **direct 时把 `nc` 设为 0**（`SetNoDelay` 运行时可调），**relay 时设 1**；`SetWindowSize(256,256)` 保留（两路共用一条会话，无法 per-path 设窗口）。切换时同步调整，并加单测覆盖。

## pair 生命周期（与 relay 解耦，H1）

**问题**：现状把 pair 的生命周期绑在 relay 上。`resetsPairKCP`（`engine.go:2160-2166`）对 `reasonLinkLost / reasonPeerGone / reasonPeerGoneProbe / reasonPeerRekeyed / reasonSecureDesync / reasonEngineClosed` 全为 true；relay 断链时 `derp connection lost` → 删 relay secure（`:1747`）→ `killSession(reasonLinkLost)` → `dropRelayKCP` → **`pair.shutdown()`**（`:2242`/`:1131`）→ `closeRelayKCPs` 把所有 pair shutdown（`:1759`/`:1149`）。统一后 direct underlay 挂在同一 pair 上，于是 relay 一抖动就把 direct 及其上所有流拆掉；之后重建的新 pair 里没有 direct，只能靠 relay 重新打洞。这与「direct 起来后 relay 可去」直接冲突；spec 旧文「relay 重连不影响 direct」只对干净替换成立，对链路丢失不成立。

**决定**：

- **pair 存活 = 任一 underlay 存活**。relay 链路丢失时只 **unregister relay underlay**，**不** `shutdown` pair、**不** 删 secure、**不** reset KCP epoch——只要还有 live direct underlay。
- 条件化触发：`resetsPairKCP(reasonLinkLost)`（及 `reasonPeerGone` / `reasonPeerGoneProbe`）**仅在无 live direct underlay 时为 true**；`closeRelayKCPs` 跳过有 live direct underlay 的 pair；relay secure 的删除（`:1747`）与 `dropSecure` 同理。
- relay 重连 = 重新 `register` relay underlay（干净替换），不重建 pair、不 re-handshake secure。
- 无 direct 时行为与现状完全一致（保持安全）。
- **判定「peer 真的没了」**：peer 重启会同时杀掉它的 direct socket；若 direct 在本方 6 s 内变 stale，watchdog 触发 unregister，此时按「无 live direct」重算重置策略即可。relay 侧误报「peer gone」但 direct 仍新鲜时，**不** 重置。
- secure **协议机制不变**，变的只是「何时丢弃/重置」的触发条件。这是本设计唯一触碰 secure 生命周期之处，需 P0 spike 验证（无 nonce 错位、无 session 泄漏）。

## 数据流：迁移走一遍

1. peer 出现 → relay pair 建立 → 流在 relay 上打开（preferred=relay）。
2. pump 触发 `maybeStartDirect` → STUN/candidates → 各 family `seedHandshakeUDP`。
3. 胜出：`registerDirectUnderlay(sock, peer)` 注册 direct；`lastRecv=now` → preferred=direct。
4. pair 的后续 KCP 段走 direct；relay underlay 仍被双读（只为回落与统计）。
5. direct 死：`lastRecv` 老化 > 6 s → unregister + preferred=relay + re-punch。KCP 在 relay 上重传在途段；上层无感。
6. relay 链路丢失但 direct 活：只 unregister relay underlay，pair/secure/epoch 保留，流继续（H1）。
7. relay 重连：重新 `register` relay underlay，pair 不变。

## 线格式

- relay：**不变**（仍 KCP-over-DERP，conv=`relayConv`，secure tag `0x00`）。
- direct：由「独立 KCP(conv=普通 hash) + secure `0x01` + smux」变为「pair 的 KCP 段（conv=`relayConv`）直接走 UDP」。锁步，无兼容负担。
- secure 记录格式不变。

## 安全

- direct underlay 入站按对端地址过滤（等价现状 kcp-go 源地址锁的强度）。
- conv 公开可算（sha256 公钥），direct 上的 KCP 控制帧理论上可被知道 conv 且能伪造对端地址者注入——与现状同级；如需增强，后续可启用 kcp-go block AEAD（非本次）。
- 加密仍在 secure 层，端到端，位于 KCP 之上；两条 underlay 共享同一条会话。

## 错误处理与边界

- underlay 写错误吞掉（返回 `len, nil`），由 KCP 重传；不返回错误（否则 kcp-go 永久致命）。
- pair `ReadFrom` 的 `io.EOF` 只保留给 pair 结束。
- 两条 underlay 都 down 时，pair 只靠 smux timeout 发现整体死亡 → 触发 mux 重建（与现状 relay 一致）。
- relay **端点替换**（干净替换）不影响 direct underlay；relay **链路丢失**按「pair 生命周期」条件化处理，不得无条件 `shutdown` pair。
- direct re-punch 时若旧 direct underlay 仍在，注册新的先摘旧的（与 `markUp` 替换旧 session 同语义，`direct.go:760`）。

## 分阶段实现

- **P0**：**H1 生命周期解耦 spike**——用现有 relay-loss 测试设施验证「有 live direct 时不 shutdown pair / 不重置 secure」无 nonce 错位、无 session 泄漏，并定下「live direct」判定与条件化触发点（`resetsPairKCP` / `closeRelayKCPs` / relay secure 删除）。
- **P1**：`pairUnderlay` 抽象 + relay/direct 两实现 + fan-in + preferred/recency + 回落 watchdog + 条件化生命周期；单元测试（可把 `spike_kcpmigrate_test.go` 的模型提升为产品测试）。
- **P2**：punch 改造（raw-UDP seed + `registerDirectUnderlay` + seed echo）；删除 direct KCP/secure/smux/`acceptLoop(direct)`/`directSmuxConfig`；`markUp`/`markDead` 语义改造；re-punch 接到 underlay 死亡 + backoff 滞回。
- **P3**：`OpenStream`/`acceptLoop`/stats/doctor/faults（含 per-path mute）收尾；e2e 场景更新；文档与 memory。

## 测试计划

- 单测（`p2p/internal/host`，`GOWORK=off CGO_ENABLED=1`，`-race -p 1`）：
  - pair 双 underlay：字节流跨 preferred 切换无损（丢/乱序/重复注入）；smux over pair 同样；不双读则饿死（负向）。
  - preferred=recency：direct 新鲜→direct；老化→relay；direct 恢复→direct。
  - 回落：direct 无入站 6 s → unregister + re-punch 触发；无数据丢失。
  - direct underlay 源地址过滤：非对端来源包被丢弃。
  - relay 端点替换与 direct 并存互不干扰。
  - **H1**：direct live 时 relay 断链 → pair/secure/epoch 保留、流不断；无 direct 时 relay 断链 → 与现状一致地重置。
  - **H2**：注册后收到对端 seed magic → 回 echo（不丢弃）；对端迟到重传仍能完成 seed。
  - **H3**：direct 抖动 → 回落后能 re-punch 恢复且 backoff 生效（不抖动风暴）。
  - **H5**：切到 direct 时 nc=0、回 relay 时 nc=1。
  - **H4**：watchdog 摘除自身 underlay 无死锁、无 goroutine/socket 泄漏。
- faults：切换点注入数据黑洞（`muteData`），验证 KCP 在 relay 上恢复、字节流无损；并提供 **per-path mute**（只静音 direct）覆盖「direct 死、relay 恢复」。
- e2e：`p2p/tests/e2e` 的 `derp-direct`、`udp-tun`；验证已开流在 direct 起来后迁移（观察 preferred / 统计）；验证 relay 断链不影响已迁移的流。
- 回归：现有 relay / secure / desync 相关测试全绿。

## 影响面与风险

- 改动大：数据面重构 + punch 改造 + **pair 生命周期/secure 重置触发条件** + faults/测试重写；relay 线格式与 secure 协议机制不变。
- 风险最高点：**H1 的 secure 重置条件化**（触及 secure-poison 历史区）、回落时延与抖动（`underlayIdle`、H3）、以及删除 direct 平面时遗漏的调用点（`dc.sess` / `dc.secure` / `dc.conv` 遍布测试）。
- 缓解：P0 先用测试设施验证生命周期解耦；P1 把 underlay/选择逻辑单元化并复用 spike 的注入手段；P2/P3 逐步删并跑全量测试。

## 已定（2026-10-05 评审）

- `capsTightKeepalive`：**本次不消费**（保留 bit 定义，避免动 caps 线格式）；pair 统一用 `smuxKeepAliveInterval/Timeout` = 3 s/15 s。`capsNoDirect` 保留（仍是设置）。若日后要更早发现「两条路都死」，直接调小 `smuxKeepAliveTimeout`，不重新引入协商。
- `underlayIdle`：起值 **6 s**（2 × keepalive 间隔），**v1 不做 hysteresis**；实测后调优。
- `spike_kcpmigrate_test.go`：**保留为可复现证据**；其模型在 P1 **提升为产品单测**（按新 `pairUnderlay` 接口适配）。

## 复审修订（2026-10-06）

- **H1（阻断级，已定）**：pair 生命周期与 relay 解耦——relay 链路丢失时，若有 live direct underlay 则不 `shutdown`、不删 secure、不 reset epoch；条件化 `resetsPairKCP`/`closeRelayKCPs`/relay secure 删除。secure **协议机制不变**。新增 **P0 spike**。
- **H2（已定）**：direct underlay 对 seed magic **回 echo**，不丢弃（防单边 punch 成功）。
- **H3（已定）**：无温备态为设计意图；对「起来后很快又死」的 direct 加大 re-punch backoff 防抖动风暴。
- **H4（已定）**：watchdog 回调不得同步 join 自身 pump。
- **H5（已定）**：切 direct 时 `nc=0`，relay 时 `nc=1`（`SetWindowSize(256,256)` 保留）。
- **M1（已定）**：`transport` 语义改为「pair 当前路径」，Status/doctor 同步。
- **M2（已定）**：faults 增加 per-path mute。
- **M3（已定）**：首个连接不再等 punch（直接在 relay 起、随后迁移），测试期望更新。
