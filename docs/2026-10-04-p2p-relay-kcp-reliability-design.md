# p2p 中继平面可靠化（KCP over DERP）设计

- 日期：2026-10-04
- 状态：设计已评审，待写实现计划
- 关联：`docs/2026-10-04-p2p-relay-session-desync-plan.md`（本设计推进其 Task 4，并取代其"明确不做"中"不定位 datagram link 根因"的边界）
- 关联：`docs/2026-09-30-p2p-e2e-encryption-design.md`

## 背景与证据

中继（DERP）单隧道的 `direct:false` 场景下，hub→spoke 大流量传输在约 1.8–2.2 MB 处必崩：

- spoke：`secure record desync ... error=p2p: bad secure record length 3291647173`，同一时刻 `datagram link down`、`link: edge failed ... read/written≈2.2MB`。
- 修复自死锁前，首次失配会让 smux `recvLoop` 永久挂死（静默、不可恢复）。该自死锁已修复并提交（`1f29500`）。
- 修复后失败从"静默永久挂死"变为"可上报、链路拆除"，但**传输仍不恢复**：新的 presentation 流被接受却 `frames=0`，吞吐不再回来。

## 根因

中继平面的字节流是**有损包路径**，而记录层与 smux 都假设它无损有序：

```
derp 包 → peerConn(字节流) → cryptoConn(AEAD 记录) → smux
```

1. **DERP 会丢包。** derper 对每个客户端有一个有界发送队列，队列满即丢——这是 relay 的设计属性，不是缺陷。客户端↔derper 之间是 TCP（可靠），丢包发生在 **derper→接收端** 这一跳。
2. **记录层是长度前缀流，丢一段即永久错位。** `[4B 长度][密文+tag]`，一次丢包让后续所有长度前缀都从密文中间读取，即 `bad secure record length`。
3. **smux 同样假设无损。** 即使关掉加密，smux 的帧也会因丢包而错位；加密只是让失败更早、更响。
4. **缺少回压链路。** 接收端应用/流变慢 → smux 会话桶（`MaxReceiveBuffer`，默认 4MB）耗尽 → `recvLoop` 停读底层 → derp 客户端停读 → derper 队列溢出 → 丢包 → 记录错位。整条链上**没有任何重传**。
5. **直连平面不受此苦，因为它有 KCP。** 直连堆栈 `UDP punch → KCP → secure → smux`（`direct.go`，`kcp-go/v5` 已是依赖）。中继平面独缺这一层。

`cryptoConn.Write` 曾忽略底层短写、并把长度前缀与正文分成两次写（已修复，`d2eff96`：单缓冲 + `writeFull` 重试）。这是次要加固，不是根因。

## 目标

- `direct:false` 的中继单隧道，把 DERP 当作**有损数据报链路**，补上 ARQ，可靠性与直连平面**完全对齐**：丢包由重传恢复，大流量能传完。
- 加密保持端到端，位于可靠层之上。
- 改动不触及 smux 及上层 link/handler 逻辑；直连平面行为不变。

## 非目标

- 不改 derper（外部 stock 二进制，其丢包策略不属于本仓库）。
- 不改 smux 协议版本（v2 评估见本文件末"未决"）。
- 不做兼容 / 协商：假定两端同时升级，线格式可自由变更。

## 架构

仅改中继平面；直连保持不变。

```
derp 包 ↔ relayPacketConn(per-peer net.PacketConn) ↔ KCP 会话
        ↔ faultConn ↔ cryptoConn(secure) ↔ smux ↔ link/handler
```

与直连平面（`direct.go:1093` 起）的包装顺序一致，唯一区别是底层：直连是 UDP 打洞 socket，中继是"以 derp 包为数据报"的适配器。

### 组件

1. **`relayPacketConn`**（实现 `net.PacketConn`，每个 peer 一个）
   - `WriteTo(p, addr)` → `derpclient.SendPacket(peer, frameData‖p)`（复用既有 `frameData` 前缀）。`addr` 忽略：目标 peer 固定。
   - `ReadFrom(p)` → 从 `pc.inbound` 取**一个数据报**（保留包边界，不拼接）。
   - `LocalAddr/RemoteAddr` 返回占位地址（两端一致即可；仓库已有 `dummyAddr`）。
   - 生命周期：`ownConn=false`，由 `killSession` 掌控，避免 KCP 关闭共享的 derp 客户端。
   - 边界：只做"数据报边界 ↔ SendPacket"映射，**不含**重传/排序——归 KCP。

2. **`relayConv()`**：由 `sha256(sorted(pub, peer))` 加域标签（区别于直连 `conv()`）取前 4 字节；重连复用同一 conv，无需握手。

3. **会话构建**（现 `sessionLocked` 中 `pc.secure.conn(pc)` 一步）：建 `relayPacketConn` → `kcp.NewConn4(relayConv(), dummyAddr{}, nil, 0, 0, false, adapter)` → `SetNoDelay(true,10,2,1)` / `SetMtu` / `SetWindowSize` → `pc.secure.conn(kcpConn)` → `faultConn` → `smux.Client/Server`（角色仍按公钥大小序）。`block=nil`（加密在上层）、无 FEC（shards 0,0），与直连一致。

注：中继平面的数据故障实际注入在**数据报层**（出站 `peerConn.Write`、入站 pump 在投递 `pc.inbound` 前丢弃），即位于 KCP **之下**，而非通过图中的 `faultConn`。这样被丢的段由 KCP 重传、记录层与 smux 不受影响——丢包注入测试依赖的正是这一行为。

### 线格式

- **复用 `frameData = 0x01`**，语义由"smux 字节流"变为"**一个 KCP 段**"。不新增帧类型。
- `frameControl = 0x00` 完全不动（punch/控制）。
- 出站：`relayPacketConn.WriteTo` 发 `frameData‖segment`。
- 入站：pump 见 `frameData` 后仍**整包**投入 `pc.inbound`；真正的变化只是消费者从 `peerConn.Read`（拼接字节流）变为适配器 `ReadFrom`（一次一个数据报）。

### 数据流

```
smux 流 → cryptoConn 记录 → KCP 分段/重传/排序 → relayPacketConn.WriteTo
        → derpclient.SendPacket(frameData‖seg) → derper → 对端 pump
        → 适配器入站 → KCP 重组 → cryptoConn 解密 → smux
```

secure 握手改在 KCP 之上进行（可靠流），因此握手本身也不可能再错位；密钥/记录层逻辑不变。

### 会话生命周期与陈旧段

- 构建/重建按上文；`killSession` 先 `Close` 旧 KCP 会话与适配器，再建新的，避免两条会话并存写同一 peer。
- 重建时使用**新适配器 + 新入站通道**，pump 只投给当前适配器。
- conv 按 pair 固定，旧段理论上可能落进新会话；缓解：新会话序号从 0 起，旧会话已推进大量段，陈旧段序号远超 `rcvwnd` 邻域会被 KCP 丢弃。此点需专门测试。

### 回压（本方案的核心收益）

- KCP 接收窗口承担缺失的回压：本地 smux/应用变慢 → KCP 接收缓冲填满 → 通告窗口收缩 → 发送端 KCP 停发；而接收端 derp 客户端**仍在持续读**（KCP 在消耗）→ derper 队列不再溢出 → **不再丢包**。
- smux 会话桶依旧存在，但有 KCP 兜底：`recvLoop` 停读会转化为 KCP 窗口收缩，而非中继丢包。
- KCP 发送窗口限制在途量，避免发送端冲垮中继队列。

## 参数（内部常量，不加配置开关）

- 可靠层**始终开启**，无开关、无新增配置项（无可信的"不可靠模式"使用场景；回滚靠回滚提交/二进制）。
- MSS ≈ 1400（客户端↔derper 为 TCP，无 IP 分片问题；中继丢一段即整段重传，故取保守值）。
- `SetNoDelay(true, 10, 2, 1)`；`SetWindowSize` 取保守默认。待实测后再决定是否需要暴露可调项。

## 失败处理

- **丢包**：KCP 段重传吸收；上层只见可靠有序流，正常情况下不再出现 record desync。
- 记录层失配路径保留为最后防线（含既有 deadlock 修复、一帧一写、短写处理），不再是预期路径。
- **KCP 会话死亡**（对端消失/长时间无 ACK）：KCP 超时 `Close` → 映射到现有 `killSession` → 重建 presentation。
- relay 的 secure 半仅在 reason 分类的 kill（rekey / desync / link loss / peer-gone）时丢弃，不因 inbound 队列非空而丢弃——队列里是 KCP 段、会重传，不构成"已花 nonce 的 secure 记录"。
- **derp 客户端整体掉线**：沿用现有 engine 的 stale 检测与重建逻辑，KCP 只是 underlay。
- 需测试 KCP 超时与 smux 3s/15s keepalive 的先后关系，确保重建后不被 smux 立即判死。

## 测试策略

1. **单元**
   - `relayPacketConn` 数据报边界：一次 `WriteTo` = 一个 `SendPacket`；`ReadFrom` 一次一包、不拼接。
   - `relayConv`：稳定、两端一致、与 direct conv 不同。
2. **故障注入**（复用 `faults`）
   - 新增"按比例丢 `frameData`（KCP 段）"的注入（现有 `dropData` 为永久丢，需概率丢）。
   - 在 5%/10% 丢包下端到端字节流仍完整、无 record desync。
   - 可用 netem 在 netns 上对 derp 链路丢包做集成。
3. **集成**：现有 `/tmp/wisper-cnt.sh`，`direct:false`，hub→spoke iperf3 30s——期望无 `secure record desync`、链路不降、传输完成。再跑丢包场景。
4. **回归**：`internal/host` 全量测试（smux 重建、keepalive、churn、直连平面、e2e 加密）必须通过；直连平面行为不变。
5. **重建**：模拟 KCP 会话被替换，验证陈旧段不破坏新会话。

门禁命令（沿用既有约定）：

```bash
cd /root/code/go-gost/p2p && export PATH="$PATH:/root/.local/go/bin:/root/go/bin" \
  && CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/...
```

## 上线/迁移

- 假定两端同时升级；无协商、无降级路径。中继可靠层始终开启。
- 不需要新旧互操作测试矩阵。

## 风险与未决

- KCP over derp 的窗口/RTT 调优：先用保守默认 + noDelay。
- 双重 keepalive 超时相互作用（见失败处理）。
- CPU 开销：按"吞吐优先"接受。
- **未决（暂缓）**：是否将 smux 升到 protocol v2（`smux.Config.Version=2`，同一 v1.5.57 已支持）。评估结论：v2 不能修复丢包，但与 KCP 正交；v2 的每流窗口可消除 v1 全会话桶的队头阻塞。决定：**先只做 KCP，v2 另议**（若 KCP 落地后 v1 实测干净，可按 YAGNI 推迟）。
- 与既有 `2026-10-04-p2p-relay-session-desync-plan.md` 的关系：本设计**推进**其 Task 4（e2e 回归）并**取代**其"不定位 datagram link 根因"的边界；Task 1–3 已落地（提交 `cdfb8d1`/`057f07b`/`0c99783`/`2075288`）。

## 实测结果

实测环境：`/tmp/wisper-cnt.sh`（`direct:false`，仅中继路径；hub→spoke iperf3 TCP，`DUR=30`）。二进制由 `/root/code/go-gost/wisper` 经 `go.work` 链接本地 `p2p`（`relay-kcp-reliability` @ `5710fe4`）。基线：修复前仅传 ~2 MB 即 `secure record desync` + `datagram link down`，且不再恢复。

### 运行 1：无丢包基线

| 指标 | 值 |
|---|---|
| iperf3 sender | 354,025,472 B，94.4 Mbit/s，retransmits=0 |
| iperf3 receiver | 354,025,472 B，93.4 Mbit/s |
| 时长 | 30.004 s（30 个 interval，完整跑满） |
| spoke `secure record desync` | 0 |
| spoke `datagram link up` | 1 |
| spoke `datagram link down` | 0 |
| spoke `link: edge failed` | 0 |
| spoke `relay session rebuilt` | 0 |
| spoke `relay kcp pair reset` | 0 |

传输完整跑满 30s，spoke 日志全程无 `secure record desync`、无 `datagram link down`、无 `link: edge failed`；唯一的 `datagram link up` 是会话建立时的一次（`20:06:08.523Z`）。端到端 TCP 层 `retransmits=0`：中继若有丢包由 KCP 在更底层吸收，iperf3 的 TCP 看不到任何重传。本次传输 354 MB，远超基线崩溃点 ~2 MB。

### 运行 2：丢包注入（未能执行）

本应使用 Task 4 的 `DropDataRate` 注入 ~5% 丢包，但**无法在给定 harness 上注入**：

- `p2p.FaultsConfig`（含 `DropDataRate`）只能经 `p2p.Config.Faults` 传入 `host.New`；它是 config-file only（无 RPC / 无 env / 无 flag），只有 `cmd/p2p` 二进制的配置文件会读取它。
- harness `/tmp/wisper-cnt.sh` 运行的是 **wisper**（另一个程序）：`tunnel/p2p_host.go` 的 `acquire()` 构造 `p2p.Config` 时只填 `Derp/Key/Stun/Direct/TLS`，**不填 `Faults`**；wisper 的 `config.P2PSettings` 与 `/api/config` 的 `P2PSettingsResp` 均无 `faults` 字段。
- 因此 hub 侧无法注入 `dropDataRate`。在不修改 Go 源码、不改 harness 的前提下（本任务约束），丢包场景无法完成。
- 替代方案（netem）也不忠实：client↔derper 是 wss/TCP，IP 层丢包由 TCP 重传吸收，不会产生 derp frame 级丢包，无法触发 KCP 重传。

跟进建议：把 `faults` 透传到 wisper 的 `P2PSettings` 与 `acquire()`（或改用 `cmd/p2p` + 含 `faults` 的配置文件做丢包 e2e），再补运行 2。

### 运行 2 补充：丢包场景改由仓库内 hermetic 测试覆盖

上述"无法在 harness 上注入丢包"的结论**不变**（wisper 的 `acquire()` 不填 `Faults`，且本任务约束下不改 Go 源码、不改 harness）。丢包场景的**正确性**证据改由仓库内永久测试补上，不再依赖手工 netns harness：

- 测试：`internal/host/session_lock_test.go` 的 `TestRelayToleratesDroppedDataFrames`，复用 `newEncryptedPair` 加密对与 `TestRelaySessionRunsOverKCP` 的往返 helper（不新建 harness、不用 `net.Pipe`）。
- 注入方式：仅在**发送端**经引擎的 `faults` 原子指针安装 `p2p.FaultsConfig{DropDataRate: 0.02}`（每第 50 个 `frameData` 帧确定性丢一帧，与故障测试的注入路径一致），接收端不注入。
- 传输量：**2 MiB**，远超 KCP 接收窗口（256 × 1400 B ≈ 350 KiB，约 6 倍窗口），足以迫使发送窗口循环并触发重传。
- 断言（全部确定性，不断言时序 / 吞吐 / 精确重传数）：
  1. 载荷按字节完整、有序到达（`bytes.Equal` 逐字节比对 2 MiB）；
  2. 两端均无 secure record 失步：secure 会话对象身份不变（失步会经 `dropRelaySecure` 重置），且 `desyncStreak` 为 0；
  3. 无中继会话重建：`relayRebuilds` / `relayRebuildPeers` 原子计数不变（丢包由 KCP 修复，而非拆会话重拨）；
  4. 两端 pair 级 KCP 会话对象身份不变（epoch 未重置）；
  5. 非空转：注入器自身计数器确认本次实际丢弃了非平凡数量的帧（实测约 33 / 1682 帧）。

### KCP 调优是否需要后续

- 无丢包下可持续 94 Mbit/s 且 TCP 0 重传，`relayKCPMtu=1400`、`SndWnd=RcvWnd=256`、`SetNoDelay(1,10,2,1)` 的保守默认值未暴露瓶颈，暂无需暴露调参开关。
- 5% 丢包场景的吞吐/重传开销因注入缺口未能实测，KCP 在丢包下的表现仍待补测后才能定论。丢包下的**正确性**（字节流完整、无 record desync、无重建）已由仓库内 `TestRelayToleratesDroppedDataFrames` 覆盖（见上文"运行 2 补充"）。

## 中继 KCP 可观测性

为判断上述保守默认值是否健康，中继 pair 的 KCP 会话新增可观测面（提交 `feat(p2p): expose relay KCP session statistics`），通过 `Status.PeerDiagnostics[peer].RelayKCP` 与生命周期日志暴露：`SRTT`/`RTO`/`RTTVar`（毫秒，来自 kcp-go 的 `GetSRTT`/`GetRTO`/`GetSRTTVar`）、`Conv`（pair 的确定性会话 id）、`Mtu`/`SndWnd`/`RcvWnd`（**配置值** `relayKCPMtu`/`relayKCPSndWnd`/`relayKCPRcvWnd`，非观测值）、`BytesSent`/`BytesRcvd`（pair 自有数据报字节计数，见 `relayKCPPair`），以及 `Live`（会话是否存在，区分"无会话"与"尚未测得 RTT 的空闲会话"）。日志里对应字段为 `kcpConv`/`kcpSrtt`/`kcpRto`/`kcpRttVar`/`kcpMtu`/`kcpSndWnd`/`kcpRcvWnd`/`kcpBytesSent`/`kcpBytesRcvd`，只出现在 pair 会话存在的重建（`relay session rebuilt`）与重置（`relay kcp pair reset`）行；重置行在会话被关闭**之前**读取，是最后观测值而非零值。一个健康的中继：SRTT 稳定、贴近链路真实 RTT，字节计数随流量单调增长，重建/重置计数不持续攀升；反之若 `kcpSrtt` 显著偏高或字节计数停滞而 SRTT 升高，提示窗口饥饿或丢包重传。

**局限**：kcp-go v5.6.72 不提供 per-session 的重传计数、cwnd、rwnd——这些要么只在进程全局 `DefaultSnmp` 里（且混入直连平面的 KCP 会话，不可作为单 pair 指标），要么是未导出的 `KCP` 内部字段。因此 `relayKCPMtu` 与窗口值仍是**未实测的默认值**，应当对照上述 SRTT 与数据报字节计数来调参；本文不把"尚未测量"当作"已经测量"呈现。

## 已知 flake

`TestDirectRepunchAfterMissedPeerGone`（`internal/host/direct_test.go`）是一个已知的、预先存在的 flake：其最后的 `roundTrip` 会间歇性超时（`direct_test.go:671: timeout`）——在 `main` HEAD 的非 `-race` 运行中约 30%，在 `d2eff96` 约 17%，因此先于本设计的中继工作存在。它在 `-race` 下从未复现，这也是 `-race` 门禁一直为绿的原因。两个成因已记录在测试本身：其一为环境性——本沙箱在负载下会间歇性拒绝 `sendmmsg` 系统调用（`EPERM`），破坏 seed 握手，CI/正常环境中不存在、也不相关；其二为直连平面 re-punch 路径上预先存在的产品竞态——一次陈旧候选的拨号可能耗尽 5s 的 `seedTimeout`，而接受侧的 `peerLive` 假阴性使其重新武装而非重新打洞，导致 re-punch 可能超过 2s 的 `punchWaitTimeout`，进而回退到数据帧刚被测试切断的中继；该竞态的精确交错仍未被刻画。本设计不触及直连平面的 re-punch 路径，故此 flake 与之无关。
