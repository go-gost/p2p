# QUIC vs KCP+smux：传输层 spike 报告

- 日期：2026-10-29
- 状态：spike 完成，未进入产品代码；本文是决策输入，不是已批准设计
- 关联：
  - `docs/2026-10-04-p2p-relay-kcp-reliability-design.md`（DERP 有界队列与丢包）
  - `docs/2026-10-05-p2p-kcp-path-migration-design.md`（直连/中继切换）
- 结论摘要：**QUIC 方向成立，但当前最值得先做的不是替换 KCP，而是给 DERP 路径加 batching。**

## 1. 要回答的问题

当前数据面是：

```text
直连：UDP 打洞 → KCP → 自定义 secure record → smux
中继：DERP 包中继 → KCP → 自定义 secure record → smux
```

要回答两件事：

1. 用 QUIC 替代 KCP+smux 是否可行、是否更快？
2. 如果可行，真正的瓶颈在 QUIC，还是在 DERP/中继路径？

## 2. 验证范围

已验证：

- 直连 UDP：KCP+smux vs QUIC，0% / 1% 随机丢包
- 真实 DERP：`gogost/derper` + p2p 的 `internal/derpclient`，`ws://`
- DERP 原始 payload 大小对吞吐的影响
- 把多个 QUIC packet 批进一个 DERP frame 的效果
- DERP-like TCP packet tunnel 作为对照

**未验证：**

- TUN datagram / IP 包路径
- 真实 WAN 的 30–100 ms RTT
- 公网丢包、移动网络、CPU 配额
- 生产 derper 的队列/限速策略
- QUIC 双向身份 pinning、0-RTT 重放安全
- KCP+smux 在同一个真实 DERP harness 上的严格 A/B

## 3. 测试方法

### 3.1 直连

- 单 connection
- `c` 个并发 stream（1 / 4 / 8）
- 每 stream 64 MiB，输出丢弃
- 每个实现预热 16 MiB
- 两次取中位数
- KCP+smux：kcp-go v5.6.72、smux v1.5.57、窗口 1024、MTU 1400、`SetNoDelay(1,10,2,1)`
- QUIC：quic-go v0.60.0、TLS 1.3、自签证书
- KCP **不含**自定义加密层；QUIC 包含 TLS。因此对比对 KCP 有利。

### 3.2 丢包

- 在客户端和服务端之间放一个 UDP 转发代理
- 双向按 1% 概率随机丢包
- 其余参数同直连

### 3.3 真实 DERP

- 本地 `gogost/derper`，`-verify-clients=false`，`ws://`
- 两个 `derpclient` 身份，互为 peer
- 在 DERP 的 `SendPacket` / `Recv` 上实现 `net.PacketConn`
- QUIC 直接使用该 PacketConn

### 3.4 DERP batching

- 每个 DERP payload 内放多个 QUIC packet：

```text
[uint16 length][QUIC packet][uint16 length][QUIC packet]...
```

- 达到 batch 上限（8 / 16 / 32 KiB）或 200 µs 定时器时 flush
- 接收端按长度前缀拆回单个 QUIC packet，再交给 QUIC
- DERP 只看到不透明 payload，不需要改 DERP 协议；两端必须使用同一 framing

## 4. 结果

### 4.1 直连 UDP

| 实现 | 丢包 | c=1 | c=4 | c=8 |
|---|---:|---:|---:|---:|
| KCP+smux | 0% | 263.7 MB/s | 260.2 MB/s | 255.6 MB/s |
| **QUIC** | 0% | **452.1 MB/s** | **452.9 MB/s** | **446.9 MB/s** |
| KCP+smux | 1% | 38.2 MB/s | 36.5 MB/s | 37.1 MB/s |
| **QUIC** | 1% | **94.2 MB/s** | **93.9 MB/s** | **94.0 MB/s** |

观察：

- 无丢包：QUIC 约为 KCP+smux 的 **1.7×**
- 1% 丢包：QUIC 约为 KCP+smux 的 **2.5×**
- QUIC 随 stream 数稳定；KCP+smux 在本配置下约 250–270 MB/s 封顶
- KCP+smux 的对比没有加密层，QUIC 有 TLS；QUIC 仍领先

### 4.2 真实 DERP：单包一帧

| 实现 | c=1 | c=4 | c=8 |
|---|---:|---:|---:|
| QUIC over DERP（无 batching） | 53.3 MB/s | 53.5 MB/s | 51.2 MB/s |

同一个 DERP 路径下，QUIC 稳定在 ~53 MB/s。**这不是 QUIC 的硬上限**，而是 DERP 每包一帧时的 per-frame/队列上限。

### 4.3 原始 DERP payload 大小

不跑 QUIC，直接发送 64 MiB 的 DERP packet：

| DERP payload | 结果 |
|---:|---|
| 1200 B | 接收端只收到约 81%，随后超时 |
| 1400 B | 接收端只收到约 81%，随后超时 |
| 4096 B | 98 MB/s（有一次超时） |
| 16384 B | **205 MB/s** |

结论：**小包、每包一个 DERP frame 时，DERP 突发会丢包并压住吞吐；更大的 payload 明显更好。**

### 4.4 DERP batching

| DERP batch | c=1 | c=4 | c=8 |
|---:|---:|---:|---:|
| off（一包一帧） | 54.7 | 53.8 | 53.7 |
| 8 KiB | 99.2 | 101.2 | 99.1 |
| 16 KiB | 100.4 | 98.9 | 96.5 |
| **32 KiB** | **113.5** | **116.3** | **112.7** |

这是目前最高价值的优化：

- 32 KiB batch 把 QUIC-over-DERP 从 **~54 MB/s** 提升到 **~113–116 MB/s**
- 提升约 **2.1×**
- c=1/4/8 都很稳定
- 32 KiB 仍在 DERP 单 packet 64 KiB 上限内
- 代价是 batching 引入最多约 200 µs 的 flush 延迟

### 4.5 DERP-like TCP tunnel 对照

| 实现 | c=1 | c=4 | c=8 |
|---|---:|---:|---:|
| QUIC over TCP packet tunnel | 99 MB/s | 103 MB/s | 103 MB/s |

这个结果用于区分“QUIC 在可靠 TCP underlay 上的能力”和“真实 DERP 的额外开销”：

- 同样 QUIC，TCP tunnel ~100 MB/s
- 真实 DERP 单包一帧 ~53 MB/s
- 差异来自 WebSocket/derper 队列，不是 QUIC
- 第一版 TCP adapter 只有 ~60 MB/s；`TCP_NODELAY` + 单次 `writev` 后到 ~100 MB/s

## 5. 相关 KCP 微基准

这些数据用于判断“继续优化 KCP”是否还有空间。测试是 KCP-only loopback，64 MiB，窗口 1024，MTU 1400，`nc=1`，与 p2p 完整栈不是同一环境，只能看相对趋势：

| 参数 | 吞吐 | 备注 |
|---|---:|---|
| 基线 | 200.4 MB/s | `SetNoDelay(1,10,2,1)` |
| `SetACKNoDelay(true)` | 226.2 MB/s | +13%，低风险 |
| `SetWriteDelay(true)` | 284.9 MB/s | +42%，加约 10 ms 延迟 |
| `resend=1` | 295.4 MB/s | 无丢包很快；丢包可能误重传 |
| `nc=0` | 11.4 MB/s | KCP 默认 cwnd 很保守 |
| socket buffer 4 MiB | 203.6 MB/s | 被 `rmem_max` 截断 |
| FEC 10/3（无丢包） | 118.5 MB/s | 30% 冗余，无丢包纯亏 |
| 窗口 2048 | 203.6 MB/s | KCP-only 已不是窗口瓶颈 |

这些是后续 KCP 优化候选，不是本文要落地的改动。当前代码已先把 KCP 窗口改为 1024。

## 6. 分析

### 6.1 直连

QUIC 的优势来自：

- 原生 stream 多路复用，不需要 smux
- TLS 1.3 内建加密，不需要自定义 secure record
- 自带丢包恢复、拥塞控制、pacing
- 连接迁移能力（本报告未验证）
- 在 1% 随机丢包下仍保持 ~94 MB/s

KCP+smux 在 1% 丢包下掉到 ~37 MB/s，说明当前 KCP 配置对丢包很敏感；加入 FEC、`ACKNoDelay`、`WriteDelay` 可能改善，但 QUIC 的起点更高。

### 6.2 中继

单包一帧的 DERP 路径有两个问题：

1. **per-frame 开销**：每个 QUIC packet ~1400 B，对应一个 DERP frame；包率约 40k pps。
2. **有界队列**：derper 对每个客户端有发送队列，队列满即丢；小包突发更容易触发。

batching 通过减少 frame 数量同时缓解两者。它不消除底层 TCP 的 head-of-line blocking；如果 DERP 的 TCP HOL 是硬约束，下一步应考虑 UDP/MASQUE 类中继。

### 6.3 为什么不直接替换 KCP

- QUIC over DERP 在 batching 后约 113 MB/s，但仍低于直连 ~450 MB/s
- DERP 的 TCP/WebSocket 队列仍然是中继上限
- KCP 在中继上已经有成熟的路径迁移、心跳、fallback 和故障注入测试
- QUIC 需要新的身份 pinning、0-RTT 重放防护、DERP PacketConn、TUN datagram 和迁移测试

**结论：QUIC 作为新 transport 并行验证，KCP 保留为默认/弱网/中继 fallback。**

## 7. 建议与后续工作

### P0：DERP batching 先落地

这是当前投入产出比最高的优化，且不依赖 QUIC 最终是否采用：

- 在 DERP 适配层实现 `[uint16 length][packet]` batching
- 默认 32 KiB batch，flush 200 µs–1 ms 可配
- 两端都支持；旧版本回退到单包一帧（需要版本/能力协商）
- 监控 derper 丢包、队列和 batch 延迟
- 用真实 WAN 复测，确认没有把延迟敏感流量拖坏

### P1：QUIC transport 原型

- 保持现有 `OpenStream/Accept` 接口不变
- 新增 QUIC transport，先双栈并存
- 直连：QUIC over UDP
- 中继：QUIC over DERP PacketConn（带 batching）
- TUN：优先评估 QUIC datagram 承载 IP 包
- 身份：TLS 证书绑定 p2p 公钥，peer allowlist + pinning
- 0-RTT 只用于可安全重放的场景

### P2：真实网络验证

- 50 ms RTT + 1% 丢包
- 4 核 / 8 核 CPU 配额
- 移动端 CPU/电量
- 生产 derper 队列与多客户端
- 与 KCP relay 做严格 A/B

### 不建议

- 不要为了 QUIC 直接删除 KCP；先双栈、先保留 fallback
- 不要把 `nc=1` 无条件用于公网直连
- 不要只换 smux/yamux；当前瓶颈不在 smux 窗口
- 不要在未验证 DERP batching 兼容性的情况下直接发版

## 8. 复现

直连 spike（KCP+smux / QUIC / 1% 丢包）：

```sh
cd /tmp/opencode/quic-spike
go run .
```

真实 DERP / batching spike 使用 p2p 的 `internal/derpclient`，需要临时模块和本地 derper：

```sh
docker run -d --name derp-spike --user 0:0 \
  -p 127.0.0.1:18999:8080 gogost/derper:latest \
  -a=0.0.0.0:8080 -stun=false -verify-clients=false -c=/tmp/derper.key
```

临时模块的 `go.mod` 需要：

```text
replace github.com/go-gost/p2p => /path/to/p2p
```

batching 的关键不是 DERP 协议改动，而是两端 PacketConn 都按长度前缀拆分/合并；核心格式见 §3.4。

## 9. 最终判断

- **直连**：QUIC 值得替换 KCP+smux；性能和丢包表现都更好。
- **中继**：QUIC 可行，但必须先给 DERP 加 batching；单包一帧的 ~53 MB/s 是路径上限，不是 QUIC 上限。
- **当前决策**：不立即替换；先做 DERP batching，再做 QUIC transport 原型和 WAN/TUN 验证。
