# p2p QUIC transport：relay + direct 单连接多路径 — design

- 日期：2026-10-29
- 状态：已评审（2026-10-29 用户确认：KCP/QUIC 全局互斥、QUIC 无 fallback、TLV 用 `tlvVersion` 字节而非新 caps bit；migration spike 已通过）；下一步 writing-plans
- 关联：`docs/2026-10-29-quic-vs-kcp-smux-spike.md`、`docs/2026-10-05-p2p-kcp-path-migration-design.md`、`docs/2026-09-30-p2p-e2e-encryption-design.md`
- 关联记忆：[[p2p-kcp-session-migration]]、[[p2p-direct-churn-and-phone-suspend]]、[[p2p-ipv6-direct]]、[[p2p-e2e-suite]]
- 证据：`/tmp/opencode/quic-migration-spike`（throwaway，未进产品代码；结论见 §5）

## 1. 意图（why）

当前数据面是：

```text
直连：UDP 打洞 → KCP → 自定义 secure record → smux
中继：DERP 包中继 → KCP → 自定义 secure record → smux
```

一个 peer 只有**一条 KCP 会话**（`relayKCPPair`），relay 和 direct 是它的两条
underlay；KCP 在换底层路径时用序号/重传兜住 cutover，smux 与上层的流无感。这条
会话是 p2p 的韧性核心：direct 掉了回 relay，relay 掉了 direct 继续。

2026-10-29 的 spike 证明 QUIC 在直连（1.7× 无丢包 / 2.5× 1% 丢包）和中继
（32 KiB batching 后 ~113 MB/s）都明显优于 KCP+smux。本设计把 QUIC 做成
**与 KCP 并列的全局数据面模式**，并且保留“一条连接、两条 underlay、流可迁移”
这一语义，而不是把 QUIC 当成又一条 KCP underlay。

目标不是替换 KCP；目标是让部署方可以通过一个全局开关选择数据面：

```yaml
transport: kcp   # 默认，现有行为完全不变
# 或
transport: quic  # relay 和 direct 都走 QUIC
```

## 2. 目标（goals）

- G1：新增全局 `transport: kcp | quic` 开关，启动时读取；`kcp` 为默认，KCP+smux
  路径的行为、线格式和性能不变。
- G2：QUIC 模式下，**每个 peer 一条 QUIC 连接**，同时承载 relay 和 direct 两条
  path；连接迁移时所有 QUIC stream 一起迁移，不重建流。
- G3：relay 路径使用 DERP 包中继 + batching；direct 路径复用现有打洞/seed/
  candidate 机制。
- G4：QUIC 流替代 smux；TLS 1.3 替代 secure record；QUIC 的丢包恢复/拥塞控制
  替代 KCP。QUIC 模式下 secure/KCP/smux 不参与数据面。
- G5：**KCP 与 QUIC 互斥二选一**：`transport` 是 host 级全局开关；QUIC 模式下
  所有 peer 都必须走 QUIC，没有 per-peer KCP fallback。peer 不支持/握手失败就是
  不可达，不偷偷建 KCP。QUIC 一旦选中就保持 QUIC。
- G6：身份仍是 p2p 的 X25519 身份：TLS 证书指纹通过 sealed `ctrlCaps` 交换，
  双向 pinning；QUIC 永远加密，不存在明文降级。
- G7：可观测：per-peer transport、当前 path、QUIC RTT、transport error、迁移
  事件计入进程内 `Status`/`PeerDiagnostic`、`p2p/doctor` 库和日志；gRPC proto
  不变，`cmd/p2p doctor` 不显示新字段（见 §8.12）。
- G8：direct 打通/掉线/重打洞时，QUIC 连接和流不重建（与 KCP pair 的
  relay↔direct 迁移语义对齐）。

## 3. 非目标（non-goals）

- 不删除 KCP+smux；不把 KCP 模式改成 QUIC 的 fallback 实现。
- **不做 KCP↔QUIC 的 per-peer fallback/混合模式**：QUIC 模式下没有 KCP 数据面；
  peer 不支持 QUIC 就是不可达。要回 KCP 只能改全局开关并重启。
- 不做 0-RTT（`Allow0RTT=false`，不使用 `DialEarly`）。
- 不做 QUIC datagram（RFC 9221）；现有 udp/ip link 继续用 2 字节长度前缀的
  stream 承载（`frameConn`），QUIC 只提供 byte stream。
- 不做多路径聚合/同时发送（不是 MP-QUIC）：同一时刻只从 preferred path 发。
- 不做运行时切换 `kcp ↔ quic`：开关启动时读取；已建立的 pair 的 transport 固定，
  要换模式就重启。
- 不做“direct 用 QUIC、relay 用 KCP”的混合模式；全局开关选的是整个 pair 的
  数据面栈。
- 不改 DERP 协议、不改 derper；batching 是两端 QUIC 模式内部的 payload framing。
- 不改 gRPC proto（冻结）；新字段只进进程内 `p2p.Status`/`PeerDiagnostic`。
- **不与 multi-DERP（`docs/2026-10-20-p2p-multi-derp-design.md`，待评审）合并**。
  QUIC v1 每 peer 只有一条 relay underlay/一个 relay path identity（当前 endpoint
  的 DERP 连接）。multi-DERP 落地后若要与 QUIC 组合，relay path 必须改成
  per-relay 身份，另做设计；v1 不做这个抽象。

## 4. 反目标（anti-goals，做到算失败）

- **QUIC 握手失败时静默降级成明文或偷偷建 KCP**。不存在明文路径；QUIC 模式下
  失败就是错误，不建 KCP。
- **共享一个 `quic.Transport` 给多个 peer**。零长度 CID 要求一个 Transport 只
  承载一条连接；跨 peer 共享会破坏 demux/迁移。每个 peer 一个 Transport。
- **把 QUIC 只当 KCP 的第三条 underlay**。QUIC 自己就是可靠传输，不能叠在 KCP
  上；那样拿不到 spike 的性能，也失去了意义。
- **在 QUIC 模式下还偷偷建 KCP 会话**。QUIC 模式和 KCP 模式二选一，避免同一
  pair 两套流平面、两套 secure 状态。
- **用默认 4 字节 CID 做多路径迁移**。spike 实锤第二次迁移会因 peer-issued CID
  池耗尽而失败；必须用零长度 CID。
- **把 relay batching 用到 KCP 模式**。KCP 模式保持一包一帧，零行为变化。

## 5. Spike 证据

### 5.1 性能（已有报告）

- 直连 0% 丢包：QUIC ~452 MB/s vs KCP+smux ~264 MB/s（1.7×）。
- 直连 1% 丢包：QUIC ~94 MB/s vs KCP+smux ~37 MB/s（2.5×）。
- QUIC over DERP：一包一帧 ~53 MB/s；32 KiB batching 后 ~113–116 MB/s。
- 详见 `docs/2026-10-29-quic-vs-kcp-smux-spike.md`。

### 5.2 Migration spike（本次，已通过）

位置：`/tmp/opencode/quic-migration-spike`（quic-go v0.60.0 / v0.63.0 均验证）。

拓扑：

```text
client ── multiPathConn ──┬── relay underlay（内存可靠包管道，模拟 DERP）
                          └── direct underlay（127.0.0.1 UDP socket 对）
server ── multiPathConn ──┘
```

验证内容：

1. 一条 QUIC 连接先在 relay underlay 上建立，双向各开一条 stream 持续发送
   4 字节序号。
2. t=1s：两侧加入 direct underlay；client 把 preferred 切到 direct。
3. t=3s：client 把 preferred 切回 relay。
4. t=5s：两侧加入**新的** direct underlay（模拟 re-punch 新 socket）；client
   再次切到 direct。
5. 断言 server 的 `conn.RemoteAddr()` 序列为
   `relay → direct → relay → direct`，且两个方向的序号流跨全部迁移无丢、无重、
   无乱序（各 5600+ 条记录）。

结果（`-race`）：

```text
path[server]: relay -> direct:127.0.0.1:54980
path[server]: direct:127.0.0.1:54980 -> relay
path[server]: relay -> direct:127.0.0.1:39817
records: client->server=5649 server->client=5649
server path transitions: [relay direct:... relay direct:...]
client path transitions: [relay]
PASS
```

关键发现：

- **client 是唯一的路径控制方，server 只跟随**。quic-go 的 server 不能主动
  `AddPath`；client 通过多路径 conn 的 preferred 写路径驱动，server 在收到新
  source 地址后走 QUIC path validation（PATH_CHALLENGE/PATH_RESPONSE），验证后
  `SwitchToPath`。
- **必须用零长度 connection ID**。quic-go 默认每端只发 `ActiveConnectionIDLimit-1`
  = 3 个 peer-issued CID；server 在 relay→direct→relay 后 CID 池耗尽，日志为
  `skipping validation of new path ... since no connection ID is available`，第二次
  direct 迁移永远不成立。给两端 `quic.Transport` 配
  `ConnectionIDGenerator: zeroCIDGenerator{}`（`ConnectionIDLen()==0`）后，迁移
  不再受 CID 池限制。
- 零长度 CID 的代价：Transport 不能按 CID demux 多条连接 ⇒ **一个 Transport
  只能承载一条 QUIC 连接**。p2p 本来就是每 peer 一个 pair/一条连接，因此每个
  peer 一个 Transport 正好；绝不能跨 peer 共享。
- client 的 QUIC `RemoteAddr()` 全程保持 relay（client perspective 不迁移），
  真实路径由多路径 conn 的 preferred 决定；server 的 `RemoteAddr()` 才变化。
- 关闭时需要 `net.PacketConn.SetReadDeadline` 能唤醒阻塞的 `ReadFrom`；否则
  `Transport.Close` 会卡在等待 read loop。
- 替换/退役一个 underlay 时，旧 underlay 的 read 错误不能透传给 QUIC transport
  （否则整条连接被误杀）；只应由当前 active underlay 或整体 close 触发失败。

### 5.3 尚未验证

- 真实 DERP + batching 与多路径 conn 的组合（batching 单独已验证）。
- TLS 证书 pinning 与 caps TLV（方案上直接，需实现/测试）。
- 真实 WAN（30–100 ms RTT、1% 丢包）、移动网络、CPU/电量。
- 多 peer（每 peer 一个 Transport）的 goroutine/内存成本。
- 长时间迁移、NAT rebinding、relay 断线重连时的 underlay 替换。
- 与 KCP 模式的严格 A/B。
- 0-RTT/重放（本设计不使用 0-RTT）。

## 6. 方案选择

### 方案 A（选中）：一条 QUIC 连接 + 双侧多路径 PacketConn

- relay 和 direct 是同一条 QUIC 连接的两条 path；流随连接迁移。
- 与现有 KCP pair 的语义 1:1 对齐，真正“一步到位”。
- 代价：自定义多路径 PacketConn、DERP batching、零长度 CID 约束、path
  validation 的时序/观测。
- Migration spike 已证明核心机制成立。

### 方案 B（未选）：每个 peer 两条 QUIC 连接（relay、direct），按流选择

- 简单，不需要迁移/path validation；但流不能迁移：长连接开在 relay 上就一直
  走 relay，direct 打通只影响新流。与现语义不一致。

### 方案 C（未选）：QUIC 只做 direct，relay 保留 KCP+smux

- 达不到“relay 和 direct 都可切 QUIC”的目标；保留两套数据面。

### 方案 D（未选）：QUIC 只作为 KCP 的 underlay

- QUIC 自带可靠传输，叠在 KCP 上拿不到性能；无意义。

## 7. 总体架构

```text
                    DERP control（sealed caps / candidates / punch）
        peer A  <──────────────────────────────────────────────>  peer B
           │                                                          │
           │   one QUIC connection per peer (zero-length CID)         │
           │   TLS 1.3, cert FP pinned via ctrlCaps                   │
           │   QUIC streams = tunnels（tcp / udp / ip link）           │
           │                                                          │
           │   multiPathConn（per peer）                               │
           │     ├── relay underlay: peerConn frameData + batching    │
           │     └── direct underlay: punched UDP socket (seed)      │
           └──────────────────────────────────────────────────────────┘
```

- **一条连接**：QUIC connection 在 relay 上建立（direct 尚未打通），direct 打通
  后加入第二条 path；路径切换时所有 stream 跟着迁移。
- **client 控制路径**：角色按公钥顺序（与现有 smux 一致）：小公钥 = QUIC client
  = 路径控制方；大公钥 = QUIC server = 跟随方。
- **per-peer Transport**：每个 peer 一个 `quic.Transport`，底层是它的
  multiPathConn；零长度 CID，一条连接。
- **transport 决策在第一条流打开前定死**：QUIC 或 KCP，二选一；之后同一 pair
  不再切换数据面栈（QUIC 内部 relay↔direct 迁移除外）。

## 8. 组件设计

### 8.1 Transport 模式（全局互斥）

`transport` 是 host 级全局选择，启动时读取一次：

```text
transport=kcp  → 所有 peer 走现有 secure+KCP+smux；不创建 QUIC 证书/Transport
transport=quic → 所有 peer 必须走 QUIC；没有 KCP fallback
```

没有 per-peer 的 `undecided → kcp` 分支，也没有 KCP↔QUIC 混合模式。QUIC 模式
下 peer 不支持/握手失败就是不可达；要回 KCP 只能改配置并重启。

触发（两个入口，必须都接上）：

- **本地需求**：`OpenStream` / `Warm` 第一次需要数据面时调用
  `ensureTransport(peer)`。
- **对端需求**：`handleControl` 收到 `ctrlCaps` 后在独立 goroutine 里调用同一个
  `ensureTransport(peer)`。只应答、从不主动 open/warm 的反向隧道 host 如果不在
  入站 caps 时启动，就永远不会 `Listen`；server 的 `Listen`/`Accept` 与 client
  的 `Dial` 都由这个入口启动。

`ensureTransport` 在 QUIC 模式下：

1. 确保 DERP 连接和 `peerConn`，发送 `ctrlCaps`（QUIC bit + cert FP +
   batch version）。
2. 等 peer caps（内部 `capsReplyTimeout`，默认 3s）：
   - caps 无 QUIC bit / 无合法 FP → 立即失败，reason=`peer-no-quic`。
   - 超时 → 失败，reason=`caps-timeout`。
3. 双方 QUIC：client 对 relay underlay 发 `Transport.Dial`，server 在同一个
   relay underlay 上 `Listen` + `Accept`，都带 `quicHandshakeTimeout`。
4. 成功 → QUIC；失败 → 返回错误，reason=`quic-handshake`，**不建 KCP**。

- 决策只由全局开关决定，不存在“这个 peer 回 KCP”的分支。
- QUIC 连接死亡后仍然重建 QUIC（relay 起步）；不会在重建时改成 KCP。
- 不在 QUIC 流存活时切到 KCP，也不在运行中改 `transport`；要换模式只能重启。
- 如果 `OpenStream` 在 caps/QUIC 建立期间被调用，等待有界（`capsReplyTimeout`
  + `quicHandshakeTimeout`）；失败返回 `p2p.ErrPeerUnreachable`（或专用
  `ErrTransportUnsupported`，见 §8.10）。

### 8.2 caps 协商与 TLS 身份

`ctrlCaps` 当前 payload 是 1 字节 caps。新格式（向后兼容，旧 peer 只看第 1 字节）：

```text
[caps 1B][tlvVersion 1B][TLV...]   # QUIC 模式；KCP 模式仍只有 [caps 1B]

tlvVersion = 1                      # TLV 容器/framing 版本，不是 QUIC 版本
TLV: [type 1B][length 1B][value...]
type 0x01 = QUIC:
  [quicVersion 1B][certFingerprint 32B][relayBatchVersion 1B]
```

- `capsQUIC = 1 << 3`（bit 0 IPv6，bit 2 no-direct 已占用；bit 1 retired 不复用）。
- **不新增 `capsTLV` bit**：caps bit 表达“能力语义”，`tlvVersion` 表达“容器
  framing”；payload 长度 + 版本字节已经自描述。旧 peer 收到带尾部的 caps 仍只
  读 `clear[0]`，忽略尾部。
- 解析规则：
  - `len(clear)==1`：旧格式，无 TLV。
  - `len(clear)>=2 && clear[1]==1`：按 1 字节 type/length 解析 TLV；未知 type
    忽略，重复 type 后者覆盖。
  - 版本未知：忽略整个 TLV 段；若 `capsQUIC` 置位则视为该 peer 不支持 QUIC。
- 只有 `capsQUIC` 置位且 QUIC TLV 合法（FP 32B、`quicVersion`/batch version
  支持）才尝试 QUIC。bit 是语义门，TLV 是参数；不是“靠 QUIC bit 决定要不要
  解析 TLV”。
- caps 帧本身用静态 X25519 `SealTo` 密封，经 DERP 控制通道传输；FP 的认证强度
  与现有 secure 会话的 `ctrlSecure` 相同。
- 收到 caps 时若本地是 QUIC 模式且尚未回过 caps，回一次自己的 caps（带自己的
  FP）；用 per-peer `capsSent` 防环。FP 变化（peer 重启）时覆盖旧值并允许重新
  握手。
- QUIC 模式下 `announceDirect`/warm 也必须带 QUIC bit + TLV，不能发 bits-only：
  `addCaps` 对“无 QUIC bit”的 caps 会清掉已学到的 FP；一个 direct off 的 peer
  没有 punch caps 帧来恢复它。
- TLS：
  - 每个 engine 在 QUIC 模式下创建时生成一个 Ed25519 自签证书（只在 QUIC
    模式生成；不在首次握手时懒初始化，避免并发首连的初始化竞态）：
    CN = base64 公钥，NotBefore -1h，NotAfter +365d，KeyUsage digitalSignature，
    ExtKeyUsage serverAuth+clientAuth。
  - 指纹 = SHA-256(DER)。
  - ALPN 固定 `p2p-quic/1`。
  - client 与 server 都提供证书；server `ClientAuth: tls.RequireAnyClientCert`。
  - 两端 `InsecureSkipVerify: true`（或等价）+ `VerifyPeerCertificate` 做
    **精确 DER 指纹比对**；没有“跳过校验”的分支。
  - 不使用 0-RTT；使用 `Transport.Dial` 而非 `DialEarly`。
- peer 重启后证书变化：新 caps 带新 FP；旧 QUIC 连接自然死亡，pair 重建。

#### 8.2.1 为什么 TLV 放在 caps，而不是单独 `ctrlQUIC` 帧

结论：**v1 放在 caps 里**，不拆单独帧。理由（含“为什么不给 TLV 单独 caps bit”）：

1. **原子性**：QUIC 决策需要同时看到“支持 QUIC 的 bit + 版本 + 证书 FP”。
   放在同一帧里，收到即完整；拆成两帧会出现“bit 已置位、FP 还没到”的窗口，
   严格 QUIC 模式下还要额外状态、超时和重发。
2. **caps 本来就是协商缝**：`direct.go` 的注释明确说 `ctrlCaps` 是
   forward-looking negotiation seam，且随每次 candidate broadcast 重发、接收端
   容忍丢失。FP 是进程生命周期的身份参数（不是像 `ctrlSecure` 那样的每会话
   ephemeral + want/ack 握手），放这里语义合适，也自然获得“重发即自愈”。
3. **兼容成本最低**：旧 peer 只读 `clear[0]`，尾部 TLV 被忽略；不需要新增
   control kind、第二套解析/重发状态。单独帧虽然旧 peer 也会忽略，但新 peer
   需要处理两种帧的到达顺序与缺失。
4. **可扩展**：TLV 可以在同一个 caps 帧里继续放 QUIC 版本、batching 版本、
   未来的 multi-DERP/其他能力参数；单独帧则每加一种能力就多一个 kind。
5. **安全等价**：两种方案都用静态 X25519 `SealTo` 密封，FP 的认证强度相同。

**不给 TLV 单独 caps bit**：caps 的 8 个 bit 是能力语义（IPv6/no-direct/
QUIC/...），TLV 是编码容器。payload 长度 + `tlvVersion` 已经自描述；再加一个
`capsTLV` bit 只是把“格式”混进“能力”，而且一个 bit 只能表达“懂/不懂”，不能
表达容器 framing 版本（长度字段宽度、critical 扩展等）。如果将来容器格式要变，
`tlvVersion` 才能让新 parser 正确分派；bit 做不到。若需要“对端懂 TLV 才发
TLV”的信号，也应由 `tlvVersion` 承担，而不是再消耗一个 bit。

更通用的扩展方式是 **TLV type 高位做 critical flag**：未知 critical TLV 让对应
能力不可用/报错，未知非 critical 忽略。v1 可以先不做（QUIC TLV 是唯一的），
但 type 空间保留这个语义，避免以后再加 bit。

接收规则：`capsQUIC` 是 QUIC 语义门；`tlvVersion` 是容器门；没有 QUIC bit 时
忽略 QUIC TLV；bit 置位但 TLV 缺失/长度非法/版本不支持 → 视为该 peer 不支持
QUIC（严格模式下报错）；FP 是 **latest-wins**，不能像 IPv6 bit 那样 OR。
TLV type/length 各 1 字节，未知 type 忽略，重复 type 后者覆盖。

什么时候该拆单独帧：如果 QUIC 协商将来长出**自己的握手/确认/重试语义**（类似
`ctrlSecure` 的 want/ack）、多种证书/ALPN 组合、或需要独立于 caps 的节流/重发
策略，再拆 `ctrlQUIC`。v1 的 34 字节固定参数不值得多一帧。

### 8.3 relay underlay：DERP PacketConn + batching

`relayQUICConn` 实现 `net.PacketConn`：

- 复用 `peerConn` 的 DERP `SendPacket`/`Recv` 和 `frameData`。
- 发送 batching（QUIC 模式内部格式）：

```text
[uint16 big-endian length][QUIC packet][uint16 length][QUIC packet]...
```

  - 默认 batch 32 KiB（DERP 单 packet 上限 64 KiB），flush 200 µs 或达到上限。
  - 每个 QUIC packet 建议 ≤ MTU（默认 1200）；batch 只是把它们装进一个 DERP
    frame，不改变 QUIC 的 packet 边界。
  - 专用 sender goroutine + 有界队列；队列满丢包，由 QUIC 重传。
- 接收：
  - `peerConn` pump 把 `frameData` payload 投递给 active data sink；QUIC 模式下
    sink 是 `relayQUICConn` 的读队列。
  - `ReadFrom` 取一个 payload，按长度前缀拆包，逐个返回；malformed/truncated
    整帧丢弃并计数/日志。
  - 读缓冲按 MTU 上限；超长 packet 丢弃。
- 控制帧（`frameControl`）仍由 pump 交给 `handleControl`，不进入 batching。
- batching version 进 caps；两端 QUIC 模式必须一致；KCP 模式完全不使用。
- relay underlay 的 `LocalAddr`/`RemoteAddr` 使用合成的 `relayPathAddr`。
- `peerConn` 的 relay 断线/重连：
  - QUIC pair 提供 `relayDown()` / `relayUp(newPC)`；只替换 relay underlay，
    **不杀 QUIC 连接**。direct 活着时连接继续；relay 回来后再把 relay underlay
    加回（非 preferred）。
  - 如果当前 preferred 是 relay 且 relay 断线，QUIC 连接会因 idle timeout 死亡；
    由 pair 重建逻辑处理（relay 恢复后重新建 QUIC）。

### 8.4 direct underlay：复用打洞与 seed

- 复用现有 `directConn` 状态机、candidate 交换、seed token echo、NAT 诊断、
  re-punch/backoff、IPv6 family、faults。
- seed 成功后的安装动作从“注册 KCP direct underlay”改为一个 transport-agnostic
  的 hook：

```go
installDirect(peer, sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte)
retireDirect(peer, sock *net.UDPConn)
```

  - KCP 模式：现有 `registerDirectUnderlay` / `clearDirectUnderlay`。
  - QUIC 模式：给 multiPathConn 加 direct underlay；client 同时把 preferred
    切到 direct；server 只加 underlay，等 QUIC path validation 跟随。
- direct underlay 仍然：
  - 按 peer source 过滤；
  - 回显迟到的 seed probe（token-aware，防 ping-pong）；
  - 3s heartbeat、6s `directUnderlayIdle` 判死；
  - 一个 socket 一个 owner，close 幂等。
- 给 multiPathConn 的 view：
  - `ReadFrom` 返回 direct peer 地址；内部循环吞掉 `os.ErrDeadlineExceeded`
    （1s 一次的 idle tick 不能透传给 quic-go 的 read loop）。
  - `WriteTo` 发往 peer；错误吞掉/返回长度，交给 QUIC 重传。
  - heartbeat/seed magic 在交给 QUIC 前过滤。
- direct 掉线：
  - client 的 heartbeat 判死 → preferred 切回 relay → retire direct underlay →
    现有 H3 backoff 重新打洞。
  - server 跟随 client 的 relay 包切回 relay；连接和流不重建。
  - 重新打洞成功后加入新 direct underlay，client 再切 preferred direct；
    QUIC path validation 重新验证新地址。零长度 CID 保证这可以反复发生。
- direct 的一个方向坏掉：client 的 heartbeat 需要双向回显，任一侧不通都会超时；
  由 client 切回 relay。server 不需要独立的路径决策。
- `directConn.sock`/`sessAt`/state/trace 继续作为“direct 是否 up”的共享状态；
  `underlayDead`/`teardown` 调 `retireDirect`，不直接碰 QUIC/KCP 内部。

### 8.5 multiPathConn（核心新组件）

per peer 一个，实现 `net.PacketConn`：

```go
type multiPathConn struct {
    role      string // client / server
    underlays map[string]*quicUnderlay // relay / direct
    preferred string                   // client only

    readCh    chan readResult          // fan-in
    deadline  time.Time
    deadlineCh chan struct{}
    // counters: reads, drops, per-underlay bytes
}

type quicUnderlay struct {
    name string
    addr net.Addr // relayPathAddr / directPathAddr（必须不同）
    pc   net.PacketConn
}
```

- `ReadFrom`：fan-in 队列；每个 underlay 一个读 goroutine；返回该 underlay 的
  **地址**。返回的地址是 QUIC path 的身份：relay 与 direct 必须不同，否则
  server 的 path manager 不会迁移。
- `WriteTo`：
  - **client**：忽略 quic-go 传入的 addr，写 preferred；preferred 不可用时回
    relay。这是“client 驱动路径”的关键。QUIC 的 client perspective 不校验
    remote 地址，所以 client 的 `RemoteAddr()` 可以一直是 relay，真实路径由
    preferred 决定。
  - **server**：按 addr 路由到对应 underlay（PATH_CHALLENGE/PATH_RESPONSE
    必须走对路径）。未知 addr 回 relay 或丢弃并计数。
- `SetReadDeadline`：必须能唤醒阻塞的 `ReadFrom`（`deadlineCh` 关闭/重建），
  否则 `Transport.Close` 卡死。
- `Close`：close 所有 underlay；read goroutine 退出；不要向 QUIC 透传“旧
  underlay 被替换”的错误。
- 有界 fan-in 队列（如 4096 packets）；满则丢并计数；QUIC 重传兜底。
- 地址：
  - `relayPathAddr{peer}`，`String() = "relay:<peer>"`；
  - `directPathAddr{netip.AddrPort}`，`String() = "direct:<addr>"`。
- **零长度 CID**：

```go
type zeroCIDGenerator struct{}
func (zeroCIDGenerator) ConnectionIDLen() int { return 0 }
func (zeroCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
    return quic.ConnectionIDFromBytes(nil), nil
}
```

  每个 `quic.Transport` 都配置这个 generator；每个 Transport 只用于一个 peer
  的一条连接。**不允许跨 peer 复用 Transport**。spike 证明默认 CID 池会在第一次
  迁移回 relay 后耗尽，第二次迁移永远失败。

### 8.6 quicPair（per-peer）

```go
type quicPair struct {
    e       *engine
    peer    derpclient.PublicKey
    role    bool // true = client（小公钥）
    mp      *multiPathConn
    tr      *quic.Transport
    conn    *quic.Conn
    listener *quic.Listener // server only
    // state, stats, accept loop stop, ...
}
```

生命周期：

- **建立（relay）**：client `tr.Dial(ctx, relayPathAddr, tlsClient, qcfg)`；
  server `tr.Listen(tlsServer, qcfg)` + `Accept(ctx)`。两端都带
  `quicHandshakeTimeout`；client 可对同一 relay underlay 重试若干次（覆盖 peer
  尚未开始 listen 的窗口）。
- **direct**：`addDirect(sock, peerAddr, token)` 加 underlay；client
  `setPreferred("direct")`；server 不设。direct 的 path validation 由 QUIC
  自动完成。
- **OpenStream**：`conn.OpenStreamSync(ctx)`，包成 `quicStreamConn`；使用现有
  `streamOpenTimeout`，peer gone 时用 `goneOpenTimeout`。
- **Accept**：`conn.AcceptStream(ctx)` 循环，每个流 `serveInbound(c, path,
  peer, peerAddr)`；`path` 在该流 accept 时取当前路径（快照，与现有 M1 口径
  一致）。
- **Close**：关闭 conn/transport/mp；不关闭 peerConn（engine 所有）。
- **连接死亡**：`conn.Context().Done()` → 通知 engine；按 §8.10 重建。
- **status**：当前 path、RTT（quic-go `Conn.ConnectionStats()`）、stream 数、
  role、bytes。

### 8.7 stream 包装与 serveInbound

`*quic.Stream` 不是 `net.Conn`，需要 wrapper：

```go
type quicStreamConn struct {
    *quic.Stream
    local, remote net.Addr
}
func (c *quicStreamConn) Close() error {
    c.CancelRead(0)          // 关接收方向
    return c.Stream.Close()  // 关发送方向（FIN）
}
```

- `SetDeadline`/`SetReadDeadline`/`SetWriteDeadline` 转发给 quic stream。
- `LocalAddr`/`RemoteAddr` 用 `streamAddr`（peer key、network）。
- `peekTag`、`frameConn`、`bridgeInbound`、`serveTargetStream` 等现成逻辑不变；
  udp/ip link 的 2 字节 framing 原样跑在 QUIC stream 上。
- `serveInbound` 的 `transport` 参数仍是 "direct"/"derp"（路径），QUIC 是底层
  transport；不改变上层 link/handler 的语义。

### 8.8 pump / peerConn 数据 sink

当前 `engine.pump` 把 `frameControl` 交给 `handleControl`，把 `frameData` 交给
KCP pair。改成 per-peer data sink：

```go
pc.setDataSink(func(payload []byte)) // KCP pair 或 QUIC relay underlay
```

- KCP 模式：sink 保持现有 `deliverInbound` 语义（队列/溢出处理不变）。
- QUIC 模式：sink 是 `relayQUICConn` 的读队列；batch 由它拆。
- sink 必须在 pump goroutine 里非阻塞（有界队列 + drop），不能把 pump 卡住。
- relay underlay 替换时切换 sink；旧 sink 的 close 不能关闭 peerConn。

### 8.9 路径切换与健康

**client（小公钥）是唯一控制方**：

- direct 成功安装 → `preferred=direct`。
- direct 心跳判死（`directUnderlayIdle`）→ `preferred=relay`，retire direct，
  重新打洞（H3）。
- relay 不可用且 direct 活着 → 保持 direct（不因 relay 断线切回一个死路径）。
- relay 恢复 → 把 relay underlay 加回（非 preferred）。
- 重新打洞成功 → 加新 direct，`preferred=direct`。

**server 只跟随**：

- 收到 client 的新 source 地址 → QUIC PATH_CHALLENGE → client 从 preferred
  路径回 PATH_RESPONSE → server 验证并 `SwitchToPath`。
- server 不能主动发起迁移；如果 server 侧 direct 坏了，由 client 的心跳检测到
  （双向回显）并切回 relay。

**健康信号**：

- direct：现有 seed-magic heartbeat（3s 发、6s 判死），在 multiPathConn 读取
  前过滤；与 KCP 模式共用。
- relay：现有 DERP keepalive/pong watchdog；relay underlay 的 read error 只标记
  该 underlay down，不直接杀 QUIC 连接。
- QUIC 自身：`KeepAlivePeriod`（默认 5s）+ `MaxIdleTimeout`（默认 15s）保活/
  检测整条连接；它不能替代 direct 心跳（path 级 vs 连接级）。

### 8.10 失败与重建（无 fallback）

| 事件 | 行为 |
|---|---|
| peer 不支持 QUIC / 无 FP | 立即失败，`ErrTransportUnsupported`；**不建 KCP** |
| peer caps 超时 | 失败，`ErrPeerUnreachable`（reason=`caps-timeout`）；不建 KCP |
| QUIC relay 建立失败 | 失败，reason=`quic-handshake`；`OpenStream` 返回错误；下次打开重试，**不建 KCP** |
| direct 打通失败 | QUIC 连接继续在 relay；现有 punch backoff 重试 |
| direct 心跳判死 | client preferred → relay；retire direct；re-punch；流不断 |
| relay 断线，direct 活着 | QUIC 连接继续；relay underlay down；恢复后加回 |
| relay 断线，当前在 relay | QUIC 连接死亡；relay 恢复后重建 QUIC（relay 起步） |
| 两条 path 都死 | QUIC 连接死亡；按 backoff 重建；流失败，上层重连 |
| QUIC 连接死亡且有流 | 流失败（QUIC 不能跨连接搬家）；pair 重建仍走 QUIC |
| 连续 QUIC 建立失败 | 按打开/重建的 backoff 重试；仍失败就报错；不回 KCP |

- **没有 per-peer fallback**：QUIC 模式下不存在“这个 peer 先 KCP”的状态；
  两种模式互斥，全局开关决定。
- **不在 QUIC 流存活时切到 KCP**：切换会丢流，而且 QUIC 模式根本没有 KCP
  数据面；要回 KCP 只能改配置并重启。
- **QUIC 连接死亡后的重建**：仍然先 relay 建 QUIC；direct 打洞随后/并行；
  成功后迁移。不会在重建时变成 KCP。
- 如果操作方需要“QUIC 失败也能用”，就把全局开关设回 `kcp` 并重启；这是部署
  决策，不是连接的自动行为。

### 8.11 配置

```yaml
transport: kcp          # kcp（默认）| quic；启动时读取，改模式需重启

quic:
  mtu: 1200               # QUIC packet 初始/固定大小；1200 最稳，1400 更快
  relayBatchBytes: 32768  # 32 KiB；DERP 单 packet 上限 64 KiB
  relayFlush: 200us       # batching 最大延迟
  keepAlive: 5s           # QUIC keepalive
  idle: 15s               # QUIC MaxIdleTimeout
  handshakeTimeout: 10s   # QUIC 建立（含 relay 窗口）
```

- 全部是 host 级（“全局”）：对该 endpoint 的所有 peer 生效；不是 per-peer
  配置。同一进程若有多个 endpoint，各自独立选择，不共享 QUIC 状态。
- `transport=kcp` 时 `quic` 段被忽略；KCP 线格式/行为不变。
- `transport=quic` 是**严格模式**：对端不支持/握手失败直接报错，不建 KCP；
  没有 `allowKCPFallback` 开关。
- 内部常量（不进配置）：`capsReplyTimeout=3s`，用于在 caps 阶段快速失败。
- 校验：mtu ≥ 1200；batch ≤ 64 KiB；idle > keepAlive；handshake > 0；
  `transport=quic` 需要 DERP 模式（有 relay URL/身份），stub 模式直接报错。
- CLI：`-transport kcp|quic`（与 `-direct`/`-ipv6` 并列）；配置文件的
  `transport` 覆盖/等价。

### 8.12 Status / doctor / 日志

进程内新增（gRPC proto 冻结，同 `RelayKCP`/`PeerDiagnostics` 的既有口径）：

```go
type QUICStats struct {
    Live      bool
    Role      string // "client" / "server"
    Path      string // "relay" / "direct"
    RTT       time.Duration
    Streams   int
    BytesSent uint64
    BytesRcvd uint64
}

// PeerDiagnostic 新增：
Transport       string // "kcp" / "quic"
QUIC            *QUICStats
DirectTransport string // "kcp" / "quic"（direct path 用的底层）
TransportError  string // "peer-no-quic" / "caps-timeout" / "quic-handshake" / ...
```

- `Status.PeerTransports` 仍用 "direct"/"derp" 表示路径；transport 细节看
  `PeerDiagnostic.Transport`/`QUIC.Path`。`pairPath`/`DirectPeers`/`DerpPeers`
  在 QUIC 模式下改为读 `quicPair` 的当前 path（client 用 preferred，server 用
  `conn.RemoteAddr()`）；`SessionState` 反映 QUIC 连接的 up/down；`RelayKCP`
  在 QUIC 模式下为空，QUIC 细节进 `QUIC` 字段。
- **可见范围**：`p2p/doctor` 库在**进程内**调用（wisper 的 `/api/p2p/doctor`）
  时可以输出 `transport`、`quic path`、`quic rtt`、`transport error`；
  `cmd/p2p doctor` 走 gRPC `StatusReply`，proto 冻结，只能显示既有字段。要让
  CLI doctor 也显示 QUIC 字段，必须扩展 `plugin` proto 和 `x/p2p` 的插件实现，
  属于独立的跨模块决策；本设计不改 proto。
- 日志事件（debug/info）：
  - `transport selected`（peer, transport, role）
  - `transport error`（peer, reason）
  - `quic handshake`（peer, role, duration, error）
  - `quic path-change`（peer, from, to, reason, rtt）
  - `quic underlay`（peer, relay/direct, installed/retired, reason）
  - `quic conn closed`（peer, error, active streams）
- 计数器：QUIC 建立成功/失败、迁移次数、transport error 次数、direct 心跳判死
  次数、batching 丢包/批次数。

### 8.13 KCP 模式保持

- `transport=kcp` 时：
  - 不生成 QUIC 证书/TLV；`ctrlCaps` payload 仍是 `[caps 1B]`。
  - pump 的 data sink 仍是 KCP pair；`deliverInbound` 行为不变。
  - direct `markUp` 仍注册 KCP underlay；`directConn` 的 seed/heartbeat/
    backoff/status 全部不变。
  - 不创建 `quic.Transport`/multiPathConn。
  - 现有测试必须全绿；新增 caps 解析对旧 payload 兼容。
- `transport=quic` 时**不存在 KCP 数据面**：不创建 `relayKCPPair`/secure/smux；
  peer 不会 QUIC 就是不可达。两种模式的代码路径互斥，不共享数据队列/secure
  会话。

## 9. 关键时序

### 9.1 首次打开（QUIC 模式）

```text
A.OpenStream(B)
  → ensure DERP + peerConn(B)
  → send ctrlCaps (QUIC bit + FP)
  → B pump handleControl(ctrlCaps) → B 回 caps + B ensureTransport
  → A/B 均决定 QUIC
  → client Dial(relay underlay) / server Listen+Accept（B 由入站 caps 启动）
  → QUIC handshake（TLS pin）
  → A opens QUIC stream → serveInbound
  → direct punch 并行/随后开始
```

- 第一流可能在 relay 上打开；direct 打通后迁移。这与现有 KCP 模式“先 relay，
  打洞后迁移”的体验一致。
- 如果 caps/QUIC 建立失败：`OpenStream` 返回错误（`ErrTransportUnsupported` /
  `ErrPeerUnreachable`）；**不建 KCP**。要回 KCP 只能改全局开关并重启。

### 9.2 direct 迁移

```text
seed ok（双方）
  → client: mp.add(direct) + preferred=direct
  → server: mp.add(direct)
  → client 的 QUIC 包从 direct source 到达 server
  → server PATH_CHALLENGE → client 从 preferred(direct) 回 PATH_RESPONSE
  → server validates + SwitchToPath(direct)
  → 双向流继续（spike 已验证）
```

### 9.3 direct 掉线 / 重打洞

```text
client direct heartbeat timeout
  → preferred=relay
  → server 收到 relay source → path validation → switch relay
  → retire direct underlay（不杀 QUIC 连接）
  → punch backoff → 新 socket seed ok
  → client/server add(new direct)；client preferred=direct
  → 重复 9.2；零长度 CID 允许无限次
```

### 9.4 relay 断线

```text
relay down (direct active):
  → relay underlay down；QUIC conn 继续 direct
  → relay reconnect: relay underlay 加回（非 preferred）
relay down (preferred relay):
  → QUIC conn idle timeout/close
  → relay reconnect: 重建 QUIC（relay 起步）
```

## 10. 安全

- TLS 1.3 + 双向证书 pinning；ALPN 固定；无 0-RTT。
- FP 只从 sealed `ctrlCaps` 接受；DERP 控制通道的认证 + NaCl box 是信任根，
  与现有 `ctrlSecure` 同级。恶意 relay 不能替换 FP。
- 重放旧 caps：旧 FP 对不上当前进程证书 → 握手失败（安全失败）；peer 会重发
  新 caps。证书按进程生成，重启即轮换。
- 没有“无证书/跳过 pin”的降级；没有明文 QUIC 以外的数据面。
- QUIC 包不额外加密（TLS 已加密）；direct source filter + seed token 继续限制
  direct socket 的注入面。
- 零长度 CID：不可用于 CID demux；一个 Transport 一条连接。该约束同时是安全
  边界（不能把别的 peer 的包路由进来）。
- batching payload 是不透明字节；DERP 不解析。

## 11. 性能与容量

预期：

- direct：spike 的 1.7×/2.5×；QUIC 的 CC/pacing 在丢包下明显优于当前 KCP 配置。
- relay：32 KiB batching 后 ~113 MB/s；单包一帧 ~53 MB/s。QUIC 模式默认启用
  batching。
- 迁移：一次 path validation（约 1 RTT）内在途数据靠 QUIC 重传/双 path 收敛；
  spike 在 loopback 上无感。
- MTU：固定 1200（默认）避免 relay（大 payload）与 direct（UDP MTU）之间的
  PMTUD 不一致；`DisablePathMTUDiscovery=true`。1400 可配，但需要现场验证。
- 每 peer 一个 `quic.Transport`：2 个 goroutine（read/send）+ TLS/连接状态；
  与现有每 peer KCP pair/pump 的量级相当，需在多 peer 场景实测。
- batching 的 200 µs flush 对延迟敏感流量是小量固定延迟；可配更小（如 50 µs）
  或更大 batch。默认取 spike 的 32 KiB/200 µs。
- 不做 MPTCP 式聚合；direct 优先，relay 保底。

## 12. 测试计划

### 12.1 单元

- caps TLV：旧 payload 兼容、QUIC bit/FP/版本、未知 TLV、截断、恶意长度。
- TLS pinning：正确 FP、错误 FP、无 FP、client cert 缺失、ALPN 不匹配；任何
  失败都不得建立连接。
- zeroCIDGenerator：长度 0；同一 Transport 只一条连接；不同 Transport 互不
  干扰。
- multiPathConn：fan-in、client preferred、server addr 路由、deadline 唤醒、
  close、underlay 替换（旧 read error 不透传）、队列满丢包计数。
- relay batching：encode/decode、按大小/时间 flush、malformed、超长、64 KiB
  边界。
- relayQUICConn：与 peerConn data sink 的交接、控制帧不进入 batching、断线/
  替换。
- direct underlay packet view：source filter、seed echo、heartbeat、timeout
  不外泄、socket 所有权/幂等 close。
- quicStreamConn：Close 双向、Deadline、peekTag/frameConn 兼容。
- direct plane hook：KCP/QUIC 两种实现的选择；`directConn` 原有测试不回归。

### 12.2 集成（进程内 + fake relay）

- **迁移**：relay 建 QUIC → 双向流持续 → 加 direct → 迁移 → 回 relay → 新
  direct → 再迁移；断言 server path 序列与数据完整性（spike 的产品化版本）。
- QUIC 与 KCP 模式各跑同一套 tunnel/datagram 测试。
- **严格互斥**：`transport=quic` + 只支持 KCP 的 peer → `ErrTransportUnsupported`，
  且断言**没有创建 KCP pair/session**；`transport=kcp` 时不创建 QUIC。
- QUIC 建立失败（坏 FP / drop relay data / 超时）→ 返回错误；断言不建 KCP；
  下一次 `OpenStream` 仍重试 QUIC。
- caps 超时/无 QUIC bit → 立即失败，不建 KCP。
- direct 心跳判死 → relay 回落 → 重打洞 → 再迁移；流不重建。
- relay 断线、direct 活着 → 连接/流继续；relay 回来 → underlay 恢复。
- 两条 path 都断 → QUIC 连接死亡 → 重建仍走 QUIC；流失败可观测。
- 多 peer：每 peer 独立 Transport；一个 peer 的迁移/失败不影响另一个。
- udp/ip link：framing、tag、target/adopt 路径在 QUIC 下不变。
- 切换模式（重启到 `transport=kcp`）后 KCP 路径恢复，QUIC 证书/Transport 不再
  创建。

### 12.3 E2E / 现场

- 真实 `gogost/derper` + Docker，`transport: quic`；relay-only、direct、
  relay→direct 迁移、direct→relay 回落。
- netem 50 ms RTT + 1% 丢包；CPU 配额；移动网络/doze。
- `CGO_ENABLED=1 go test -race -count=1`；多 peer 压测；长跑（迁移循环）。
- 与 KCP 模式严格 A/B（直连吞吐/丢包、relay batching、迁移耗时、内存/
  goroutine）。
- 旧 peer/旧配置兼容：KCP 模式 wire 不变；QUIC 模式要求两端都升级，对旧 peer
  直接报错（**不 fallback**）。

## 13. 兼容与发布

- 默认 `transport=kcp`，发布即可用；QUIC 是 opt-in。
- **KCP 与 QUIC 全局互斥**：同一进程只启用一种数据面。QUIC 模式要求两端都
  升级；对旧 peer 直接报错，不自动回 KCP。要回 KCP 必须改配置并重启。
- `ctrlCaps` TLV 向后兼容；旧 peer 忽略尾部（QUIC 模式下旧 peer 仍会因缺少
  QUIC bit 而报错，这是预期）。
- DERP batching 只在 QUIC 模式内使用；不影响 derper/其他客户端。
- gRPC proto 不变；新观测字段仅进程内。
- 依赖新增 `github.com/quic-go/quic-go`（建议 v0.63.x；spike 同时验证了
  v0.60/v0.63）。二进制体积/启动成本需在发布前记录。
- 回滚：`transport=kcp` 即回到现有路径；QUIC 模式没有持久化状态/迁移，回滚
  只需重启。
- 发布顺序建议：配置/caps/TLS + QUIC relay → direct 迁移 → 错误/观测 →
  batching 调优 → WAN/E2E → 文档/发布说明。默认始终 kcp。

## 14. Decisions / open questions

### 14.1 已定（我的 call，可在评审推翻）

- D1：一条 QUIC 连接 + 双侧多路径 PacketConn；client（小公钥）驱动，server
  跟随。
- D2：每 peer 一个 `quic.Transport`，零长度 CID；不跨 peer 共享。
- D3：TLS 证书 FP 放 `ctrlCaps` TLV；双向 pin；无 0-RTT。
- D4：relay 先建 QUIC，direct 后加；direct 复用现有 seed/打洞。
- D5：relay batching 32 KiB / 200 µs，QUIC 模式默认开启。
- D6：全局 `transport: kcp|quic`，启动读取；默认 kcp；QUIC 模式在首流前定死。
- D7：**KCP 与 QUIC 全局互斥，QUIC 无 fallback**（2026-10-29 用户决定）。
  QUIC 模式下 peer 不支持/握手失败即错误，不建 KCP。
- D8：QUIC 流存活时不死切 KCP；连接死亡后重建 QUIC；要回 KCP 只能改配置并
  重启。
- D9：不做 0-RTT/datagram/多路径聚合/运行时模式切换。
- D10：MTU 默认 1200，`DisablePathMTUDiscovery=true`。
- D11：QUIC v1 单 relay underlay；不与 multi-DERP 组合（按“简单处理”决定）。

### 14.2 已无阻塞问题（原 open items 的处理）

- O1：已定（用户 2026-10-29）：KCP/QUIC 互斥，QUIC 无 fallback。
- O2：已定：开关启动时读取，重启生效；“选择了 QUIC 就保持 QUIC”。
- O3：取 1200 默认（D10）；需要更快时可配 1400，现场验证。
- O4：batching 参数按 §8.11 暴露为配置，默认值即 spike 值。
- O5：不复制 `/tmp` 的 throwaway spike；实现阶段用产品化的
  `TestQUICConnectionMigratesAcrossUnderlays` 覆盖同样的路径序列和数据完整性。
- O6：已定：不做 KCP 温备；QUIC 失败就是错误/重建 QUIC。
- O7：已定（按“简单处理”）：QUIC v1 单 relay underlay，不与 multi-DERP 组合；
  未来若要组合，relay path identity 需要改成 per-relay，另做设计。

### 14.3 Builder check（已完成）

独立 subagent 按 `builder-check-prompt.md` 读过本文，提出 5 个问题；处理如下：

- **已修（文档内）**：
  - Q1 KCP fallback 后何时重试 QUIC：**已因用户决定互斥/无 fallback 而消失**；
    QUIC 连接死亡后只重建 QUIC。见 §8.1、§8.10。
  - Q2 gRPC doctor 看不到新字段：明确进程内 `p2p/doctor` 可见、`cmd/p2p doctor`
    走冻结 proto 不可见；扩 proto 是独立决策。见 §8.12。
  - Q3 旧/KCP-only peer 的 caps 等待：QUIC 模式直接失败；内部
    `capsReplyTimeout=3s`，无 QUIC bit 立即 `peer-no-quic`，超时 `caps-timeout`。
    见 §8.1、§8.11。
  - Q4 入站 caps 是否触发 server Listen：明确 `handleControl(ctrlCaps)` 也调
    `ensureTransport`，反向隧道由入站 caps 启动 server。见 §8.1、§9.1。
  - Q5 multi-DERP：按“简单处理”决定 QUIC v1 单 relay，不与 multi-DERP 组合。
    见 §3、§14.1 D11。
- 其余为 builder 可自行决定的事项，不阻塞。
