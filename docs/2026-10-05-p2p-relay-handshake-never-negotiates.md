# p2p relay 平面首次握手从不协商：证据记录与待查清单

- 日期：2026-10-05
- 状态：**仅记录，未定位**。断点已收窄到 hub 的 DERP 连接侧。
- 关联：`docs/2026-10-04-p2p-relay-session-desync-plan.md`（**不是同一个问题**，见下）
- 关联：`docs/2026-10-04-p2p-relay-kcp-reliability-plan.md`（**修不了这个**，见下）

## 症状

hub（`192.168.100.100`，`gogost/wisper:latest`，`1.8.4-dev`）上两个辐条
（`XSj5EDZ…` vscode-docker、`zRiIjY4…` pixel-9）加一个本地新建辐条，全部无法注册。

hub 事件流反复出现：

```
spoke "zRiIjY4…" refused: claimed 10.10.100.250, which is not assigned to it
    — claimed [10.10.100.250], assigned 10.10.100.2
```

两个辐条广播的恰好是自己保存的那一行却被拒，且 hub 报出的 `assigned`（`.2`/`.3`）
在保存的 `peer_ips`（`.123`/`.250`）里根本不存在。**这本身是另一个待查问题，见末尾。**

真正阻断一切的是 p2p 层。辐条侧唯一报错：

```
punch gfyuoMdKHdqS-LjNTqd6x6V5YJhpnU5ebhF-Qpfo1DI failed: p2p: peer encryption required
```

hub 侧 `derp: keepalive` 正常（`pongAge≈29.99s`、`pongs` 稳定递增），DERP 通道是活的。

## 关键计数（hub `/api/p2p` 与容器日志）

| 指标 | 值 | 含义 |
|---|---|---|
| `relay session refused: … did not negotiate it` | **38** | `ensureSession` 握手重试跑完仍未 settle |
| `secure:` 前缀日志（debug + warn 合计） | **0** | 一条 ctrlSecure 帧都没到 `handleControl` |
| `secure record auth failed` / `bad secure record` / `record boundary` | **0** | **无 desync 签名** |
| `p2p_punch_attempts` | 128 | 打洞尝试 |
| `p2p_punch_success` | **0** | 打洞从未成功 |
| `derp_peers` | **0** | **DERP 平面上没有任何 peer** |
| `direct_peers` | 0 | 直连平面也没有 |
| hub 全部 warn | 4 条，全是 `no route for ff02::16, packet discarded` | mDNS multicast 噪声（`tun/p2phandler.go:85`），与本问题无关 |

## 已逐层排除的位置（不要重查）

engine 与 derpclient 之间的每一层都读过，都正常：

- `pump`（`engine.go:1331-1389`）：`Recv` 错误处理、`stale` 提前 return、`clearGone`、
  `frameControl`→`handleControl`（1355-1357）、`frameData`→peerConn（1359+）、fault 注入点。正常。
- `handleControl`（`1409-1478`）：`ctrlSecure` 分支逻辑自洽，**从未被调用**。
- `sendControl` / `sendSecureHalf`：只在 `c == nil` 或 faults `muteCtrl` 时返回 error。
- `secureSessionFor` / `dropRelaySecure` / `secureKey{peer, transport}` 缓存：一致。
- `deriveFor`（`secure.go:545-574`）：HKDF info `"p2p-session-v1"+transport` 与 salt
  （两 ephemeral 按字节序拼接）对两端对称；方向由 `bytes.Compare(localPub, peerPub) < 0`
  决定，两端算出相反结果 → 自洽。**无 bug**。
- `internal/derpclient/derpclient.go` 整层干净：`SendPacket`（343）只做 `len(pkt) > MaxPacketSize`
  检查后原样 `dst‖pkt` 转发；`Recv`（381-428）原样交付 `body[keyLen:]`。DERP 线协议层根本没有
  ctrlSecure 概念（`frameSendPacket` 是不透明字节），`default: // Unknown frame type: skip`
  只针对 DERP 自己的帧类型。

`errEncryptionRequired` 定义在 `secure.go:26`：**加密是强制的，不降级明文**
（"a session that did not negotiate keys is refused, never built as plaintext"）。
这条设计使故障表现为「全辐条对称失效」而非「部分降级」。

## 两条必须记住的陷阱

**1. `frames=N` 不能证明 peer 帧到达。** `derpclient.Recv` 在 `switch` **之前**执行
`c.recvN.Add(1)`（`derpclient.go:388-389`），所以 `frameKeepAlive` / `framePong` /
`framePeerPresent` 三个 no-op 分支也照样把 `frames` 加一。hub 的 `frames` 每 30 秒约 +25
而 `pongs` 每 30 秒 +1，量级上是中继自身控制流量。**我先前据此得出「derper 在正常转发」的
结论是错的，已作废。**

**2. 日志级别会让「缺席」变成噪音。** `secure: send half failed`（1899/1920）、
`secure: bad box`（1441）、`secure: bad half length`（1450）、`secure: respond failed`（1472）
全是 **Debug** 级；`secure: unusable peer half`（1466）与 `did not negotiate it`（1935）是 **Warn** 级。
hub 日志有 33 条 debug（级别是开着的），所以这批 debug 的缺席是**真信息**。

## 推断的故障链

1. hub 周期性 `SendPacket` 发 `frameControl‖ctrlSecure`，DERP 通道本身活。
2. **对端从未连上这个 derper**（`derp_peers: 0`），derper 无从转发 → 帧送不到。
3. 对端也没连上，自然不回 half。
4. 两边 `ready` 恒 false → 38 次 `did not negotiate`。
5. 加密强制，谁都不降级 → 全辐条对称失效；`direct` 打洞成功也救不了
   （`direct.go:1191` 是同一条 err，direct 只是另一份 session 与另一条 KCP underlay，
   控制帧同样要经 derper 送达）。

打洞全败的原因日志给出确切线索：`derp.ginuerzh.top → 49.234.181.43`，hub 公网出口
`61.170.225.232`，而 hub 学到的对端候选**也是** `61.170.225.232` —— 同一公网地址。
hub 在 `192.168.100.0/24`，学到的对端内网地址 `10.42.0.180`（hub 路由不到），公网侧两边
都在同一 NAT 出口，**对称 NAT 打洞不成立**。

## 为什么现有两份计划都不修这个

- **desync 计划**：假设 secure 已协商、只是会话替换后 nonce 错位。当前连传输都没有。
  签名也不符（desync 的 `auth failed` / `bad secure record length` 计数为 0）。
- **KCP 可靠化**：KCP 会话的**第一个段本身也要经 `SendPacket`**。帧送不到，加多少 ARQ
  都没用 —— 它解决「丢了」，不解决「连不上」。

## 待查清单（按判别力排序）

1. **对端的 `/api/p2p`。** 这是唯一能一刀切开的判据。
   - 若对端 `derp_peers` 也是 0 → 问题在 derper 接受连接这一侧（第三方公共 derper
     `wss://derp.ginuerzh.top:8443/derp`，可能有限制）。
   - 若对端有 `derp_peers` 而 hub 是 0 → 问题在 hub 的 derp 客户端注册
     （看 `handshake()`、`frameClientInfo` 有没有成功）。
   我手上没有 pixel-9 / vscode-docker 的访问权（只有 `ssh pi@192.168.100.100` 与 hub）。
2. **hub derp 注册路径**：`handshake()` → `frameServerKey` / `frameClientInfo` /
   `frameServerInfo` 三步是否都成功，有无错误日志。
3. **保存值 vs 运行时分配的不一致**（与 p2p 无关，独立问题）：保存的 `peer_ips`
   是 `.123`/`.250`，hub 报 `assigned .2`/`.3`。用户说 `.2`/`.3` 是手动改的，但保存配置里没有。
   可能是 hub 未重载、或运行时重算。需要一次受控保存来判定（注意：**PUT `/peers` 是整表替换，
   必须带全量列表**）。

## 环境备忘

- 本地构建用的就是含 desync 修复的本地 p2p（`go.work` 的 `use` 含 `./p2p`，领先 v0.10.1 共 46 个
  提交），故障照旧 → 那些提交确定没修掉它。**但 CI 构建无 workspace**，`wisper/go.mod` 只钉
  `p2p v0.10.1`，**desync 修复根本不在 hub 镜像里**。hub 跑的是未修 desync 的 v0.10.1
  却报另一个错。
- 本机 `10.42.0.211/24`，hub 在 `192.168.100.100/24` 经 `10.42.0.1` 路由。hub 无法路由到
  `10.42.0.x`。
- `p2p` 模块门禁：`CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/...`
  （通配 `./...` 会挂）。