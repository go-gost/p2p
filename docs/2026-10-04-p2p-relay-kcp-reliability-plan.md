# p2p 中继可靠化（KCP over DERP）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `direct:false` 的中继单隧道在 derper 丢包下不再失步/崩掉，把 DERP 当作有损数据报链路补上 ARQ，可靠性与直连平面对齐。

**Architecture:** 中继堆栈由 `derp 包 → peerConn → cryptoConn → smux` 改为 `derp 包 → relayPacketConn(net.PacketConn) → KCP → cryptoConn(secure) → smux`，包装顺序与直连平面（`direct.go` 的 `KCP → secure → smux`）一致，仅底层换成以 derp 包为数据报的适配器。复用 `frameData`，不新增帧类型、不加配置开关、不做兼容。

**Tech Stack:** Go 1.27；`github.com/xtaci/kcp-go/v5`（已是依赖，直连已用）；`github.com/xtaci/smux v1.5.57`；`internal/host/secure.go` 的 `chacha20poly1305`/X25519；stock tailscale derper。

**Spec:** `docs/2026-10-04-p2p-relay-kcp-reliability-design.md`

## Global Constraints

- 绝不修改 `core/`；代码注释只用英文。
- 工作目录 `p2p/`（模块 `github.com/go-gost/p2p`）；门禁：`CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/...`（`./...` 会挂）。
- `go` 不在 PATH：`export PATH="$PATH:/root/.local/go/bin:/root/go/bin"`。
- 可靠层**始终开启**，不新增配置项/开关。
- 复用 `frameData = 0x01`，**不新增帧类型**；`frameControl` 不动。
- 不改 smux 参数与协议版本；不改 derper；不改直连平面行为。
- 每个 Task 末尾的提交步骤需用户点头后再执行。

## Review Focus

以下情形规格未逐一写死、实现者最可能踩坑；每条都在对应任务里用测试钉住：

1. **重建后陈旧 KCP 段污染新会话** —— 新会话应从旧段被序号窗口拒绝起步，重建后仍能通信。Task 3。
2. **KCP 超时 vs smux 3s/15s keepalive 竞争** —— 一方超时触发重建后不得被另一方立即判死、升级为重建风暴。Task 3。
3. **适配器缓冲小于数据报导致截断** —— MSS ≤ KCP 读缓冲，`ReadFrom` 不得丢字节。Task 1。
4. **带内在途数据报下的本地 kill** —— 复用既有的"重建即重新握手"语义，不得让新会话首记录错位。Task 3。
5. **直连平面回归** —— direct 的 `rekeyIfUsed`/KCP/smux 行为不得改变。Task 2/4 的既有测试。

---

### Task 1: relayPacketConn 数据报适配器与 relayConv

**Files:**
- Create: `internal/host/relaykcp.go`
- Test: `internal/host/relaykcp_test.go`

**Interfaces:**
- Produces:
  - `func relayConv(a, b derpclient.PublicKey) uint32` —— `sha256(sorted(a,b) ‖ "relay")` 前 4 字节，大小序交换后相等，且与 `directConn.conv()` 不同。
  - `type relayPacketConn struct` 实现 `net.PacketConn`：
    - `func newRelayPacketConn(pc *peerConn) *relayPacketConn`
    - `WriteTo(p []byte, _ net.Addr) (int, error)`（转调 `pc.Write`，即 `frameData‖p` 的 `SendPacket`）
    - `ReadFrom(p []byte) (int, net.Addr, error)`（从 `pc.inbound` 取一个数据报）
    - `Close() error`、`LocalAddr()/RemoteAddr() net.Addr`（返回 `dummyAddr{}`）、三个 `SetDeadline` no-op。
- Consumes: `peerConn`（`inbound chan []byte`、`Write`、`closeCh`）、`dummyAddr`、`derpclient.PublicKey`。

- [ ] **Step 1: 写失败测试**

`relaykcp_test.go`：
- `TestRelayConvStableAndDistinct`：`relayConv(a,b)==relayConv(b,a)`；对同一对稳定；与用相同两 key 手工计算的 `direct` 风格 conv 不同。
- `TestRelayPacketConnDatagramBoundary`：用既有 `peerConn` 测试装配方式（参考 `session_lock_test.go`/`engine_test.go` 里构造 peerConn 的 helper，勿自造整套 engine）构造 `pc`，向 `pc.inbound` 注入两个包 `packetA`、`packetB`；`ReadFrom` 两次分别**恰好**返回 `A`、`B`（字节与边界均相同，不拼接）；`WriteTo` 一次只调用一次发送（断言 `pc.inbound` 之外的发送计数/或用一个记录调用的假 client）。
- `TestRelayPacketConnReadFromTruncatesToBuffer`：`ReadFrom` 传一个小于数据报的 `p`，返回 `len(p)` 且不 panic（钉住 Review Focus 3 的缓冲契约；正常情况下 MSS ≤ 缓冲，不会走到这里）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/code/go-gost/p2p && export PATH="$PATH:/root/.local/go/bin:/root/go/bin" && CGO_ENABLED=1 go test -race -count=1 -run 'TestRelayConv|TestRelayPacketConn' ./internal/host/`
Expected: FAIL（`relayConv`/`newRelayPacketConn` 未定义）。

- [ ] **Step 3: 实现**

在 `relaykcp.go` 中实现上述类型与函数。要点：`relayConv` 与 `directConn.conv`（`direct.go:858`）同构但追加域标签；`ReadFrom` 用 `select { case pkt := <-pc.inbound: ...; case <-pc.closeCh: ... }` 并在 `closeCh` 后先排空一次入站再返回 `io.EOF`（对齐 `peerConn.Read` 的排空语义）；`ReadFrom` 对 `len(pkt) > len(p)` 按 UDP 语义截断返回。`WriteTo` 忽略 addr。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -run 'TestRelayConv|TestRelayPacketConn' ./internal/host/`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/host/relaykcp.go internal/host/relaykcp_test.go
git commit -m "feat(p2p): datagram adapter and conv for the relay KCP layer"
```

---

### Task 2: 中继会话构建改用 KCP underlay

**Files:**
- Modify: `internal/host/engine.go`（`sessionLocked` 中 `underlay, err := pc.secure.conn(pc)` 一段，约 `engine.go:1652`；`peerConn` 增加 `kcp *kcp.UDPSession` 字段）
- Test: `internal/host/session_lock_test.go`（追加）

**Interfaces:**
- Consumes: `newRelayPacketConn`、`relayConv`（Task 1）、`kcp.NewConn4`、`pc.secure.conn`、`smux.Client/Server`、`smuxKeepAliveInterval/Timeout`。
- Produces: `func (pc *peerConn) newRelayKCP() (*kcp.UDPSession, error)` —— 建适配器 → `kcp.NewConn4(relayConv(pc.e.pub, pc.peer), dummyAddr{}, nil, 0, 0, false, adapter)` → `SetNoDelay(true,10,2,1)` / `SetMtu(relayKCPMtu)` / `SetWindowSize(relayKCPSndWnd, relayKCPRcvWnd)`，并把会话存到 `pc.kcp`。常量 `relayKCPMtu = 1400`、`relayKCPSndWnd = 256`、`relayKCPRcvWnd = 256`。

- [ ] **Step 1: 写失败测试**

`session_lock_test.go` 追加 `TestRelaySessionRunsOverKCP`：用既有会话装配建立 A/B 两个 relay `peerConn`，`ensureSession` 后断言两侧 `pc.kcp != nil` 且 `pc.sess != nil`；通过 smux 打开一条流互发一段字节，断言往返一致（证明 `derp→adapter→KCP→secure→smux` 全链路通）。复用 `session_lock_test.go` 既有的会话装配 helper，勿自造 `net.Pipe` 整套。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -count=1 -run TestRelaySessionRunsOverKCP ./internal/host/`
Expected: FAIL（`newRelayKCP` 未定义 / `pc.kcp` 为 nil）。

- [ ] **Step 3: 实现**

在 `engine.go` 会话构建处，把 `underlay, err := pc.secure.conn(pc)` 改为先 `kcpConn, err := pc.newRelayKCP()`，再 `pc.secure.conn(kcpConn)`；`newRelayKCP` 按 Interfaces 实现。`pc.kcp` 在 `peerConn` 结构体登记。`killSession`/重建路径关闭旧 `pc.kcp`（`Close`），避免两条 KCP 会话并存。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -run TestRelaySessionRunsOverKCP ./internal/host/`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/host/engine.go internal/host/session_lock_test.go
git commit -m "feat(p2p): run the relay session over a KCP underlay"
```

---

### Task 3: pair 级 KCP 会话 —— clean-kill epoch 复位与陈旧段安全

> 修订依据：Task 2 实测发现，**单边 clean kill（保留密钥）会让重建侧的 KCP 会话从 sn=0 重启，而对端仍存活的旧会话继续发高序号段；kcp-go 把这些段当空洞缓存并 ACK，secure 计数器又让对端 smux 永不超时，于是 35s 内无法自愈（活锁）**。因此 KCP 会话必须与 adapter 解耦。

**Files:**
- Modify: `internal/host/engine.go`（KCP 会话从 `peerConn` 迁到 pair 级持有者；新 adapter 注册为当前端点；`killSession` 按 kill 原因决定是否关闭 KCP）
- Modify: `internal/host/relaykcp.go`（可换端点的 `PacketConn` 代理：KCP 会话捕获代理，代理把 `ReadFrom`/`WriteTo` 转发到当前注册的 adapter）
- Test: `internal/host/session_lock_test.go`（追加）

**Interfaces:**
- Consumes: `newRelayPacketConn`、`relayConv`（T1）、`newRelayKCP`/`pc.kcp`（T2）、`e.secure` 的 pair 级生命周期范式（"one per (peer, transport), outliving this adapter"）、`dropRelaySecure`、`sessionEndReason`。
- Produces: KCP 会话与 conv 绑定在 **pair（peer, transport）级**，跨 adapter 替换存活；adapter 作为可换端点注册；`killSession` 仅在 rekey / desync / 失链 / 遗弃类 kill 时 `Close` KCP，clean kill 保留它，smux 与 crypto 记录层照旧在其上重建。

- [ ] **Step 1: 写失败测试**

- `TestRelayCleanKillKeepsPairKCPAndRecovers`：复现 `TestInboundRecoversAfterAdapterClosed` 的形状（A 侧 clean kill、密钥保留、B 侧不动）；断言 A 的 KCP 会话跨 adapter 替换**存活**（会话标识未变），且 kill 后双方能重新互通并跑通新流（原失败测试必须转绿）。
- `TestRelayKCPClosedOnRekeyAndLinkLoss`：rekey / 失链类 kill 后 KCP 会话被 `Close`，下一次 build 新建（conv 不变、两端序号从 0 对齐）。
- `TestRelayKCPRebuildConvergesOnce`：一次 clean kill 只让 `relayRebuilds` +1，不出现连续重建或活锁（钉住 Review Focus 2）。
- 若 Task 1 遗留的 closeCh drain/EOF 分支仍无覆盖，在本任务顺手补上（约 10 行）。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -count=1 -run 'TestRelayCleanKill|TestRelayKCPClosed|TestRelayKCPRebuild' ./internal/host/`
Expected: FAIL（KCP 仍随 adapter 一起死）。

- [ ] **Step 3: 实现**

把 KCP 会话移到 pair 级持有者（与 `e.secure` 同构），并让 KCP 捕获一个**可换端点代理**而非具体 adapter：新 `peerConn` 建立会话时把自己注册为该 pair 的当前端点；`ReadFrom`/`WriteTo` 转发到当前端点（端点失效时按既有 closeCh/drain 语义退化为 EOF）。`killSession` 按 `sessionEndReason` 分类：仅 rekey / desync / 失链 / 遗弃类关闭 KCP 会话，clean kill 保留。pair 被移除或 engine 关闭时必须关闭 pair 级 KCP（不得泄漏 goroutine）。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/`
Expected: PASS（含既有 direct/rekey、e2e-encryption、session_lock 全绿）。

- [ ] **Step 5: 提交**

```bash
git add internal/host/engine.go internal/host/session_lock_test.go internal/host/secure_test.go
git commit -m "fix(p2p): rebuild the relay KCP session without stale segments"
```

---

### Task 4: frameData 的概率丢包注入

**Files:**
- Modify: `internal/host/faults.go`（新增按比例丢 `frameData` 的注入，风格对齐既有 `dropData`/`dropCtrl`/`dropPong`）
- Test: `internal/host/faults_test.go`（追加）

**Interfaces:**
- Consumes: `faults` 现有原子开关与 `maybeControlled`/`muteData` 风格；`peerConn.Write` 的注入点。
- Produces: `faults.dropDataRate`（或等价的确定性/概率丢方法，如 `func (f *faults) dropDataPacket() bool`），由现有 `p2p.FaultsConfig` 暴露比例（默认 0）。

- [ ] **Step 1: 写失败测试**

`faults_test.go` 追加 `TestFaultsDropDataRate`：配置固定比例/固定种子后，多次调用丢包判定，实际丢包比例落在期望区间；比例为 0 时不丢。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -count=1 -run TestFaultsDropDataRate ./internal/host/`
Expected: FAIL。

- [ ] **Step 3: 实现**

在 `faults.go` 增加按比例丢包判定并在 `peerConn.Write` 的发送前调用（仅中继 `frameData` 路径）；配置项接入 `p2p.FaultsConfig`（既有字段风格）。注意：这与 KCP 的重传直接配合——丢的段应由 KCP 补齐。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/`
Expected: PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/host/faults.go internal/host/faults_test.go
git commit -m "test(p2p): probabilistic loss injection for relay data frames"
```

---

### Task 5: 端到端验证

**Files:**
- Modify: `docs/2026-10-04-p2p-relay-kcp-reliability-design.md`（追加"实测结果"小节）
- 复用：`/tmp/wisper-cnt.sh`（hub/spoke netns + iperf3）

**Interfaces:**
- Consumes: 前四个 Task 的二进制；`faults` 丢包注入（Task 4）。

- [ ] **Step 1: 无丢包基线**

Run: `DUR=30 /tmp/wisper-cnt.sh`
Expected: hub→spoke iperf3 完成；spoke 日志**无** `secure record desync`、**无** `datagram link down`；吞吐达到链路量级。

- [ ] **Step 2: 丢包场景**

用 Task 4 的注入（如 5%）重跑 Step 1。
Expected: 仍无 record desync；传输完成（KCP 重传补齐）；记录吞吐与重传开销。

- [ ] **Step 3: 记录结果**

在 spec 文档追加"实测结果"小节：两次数字、是否出现 desync/链路重建、以及 KCP 调优是否需要后续调整。

- [ ] **Step 4: 提交**

```bash
git add docs/2026-10-04-p2p-relay-kcp-reliability-design.md
git commit -m "docs(p2p): relay KCP reliability end-to-end results"
```

## 明确不做（本轮）

- 不改 smux 协议版本（v2 暂缓，见 spec"未决"）。
- 不改 derper / 不新增中继队列控制。
- 不做新旧互操作/协商（两端同升级）。
- 不引入 FEC（shards 0,0），不暴露 KCP 调参配置。
