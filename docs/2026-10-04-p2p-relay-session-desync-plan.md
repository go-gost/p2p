# p2p relay 会话重建后 secure 层永久失步 修复实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 relay 传输在 smux 会话被替换后能够真正自愈——不再出现"新会话第一个 AEAD 记录就失败、之后每 15s 重建一次直到进程重启"的永久失步。

**Architecture:** 把 relay 安全会话的存续期从"跨任意多次 mux 会话"缩短为"跨一次 mux 会话"。任何替换或本地杀死 relay 会话的路径都调用既有的 `dropRelaySecure`，强制下一次构建用新 ephemeral 重新握手（direct 路径已用 `rekeyIfUsed` 做同样的事，relay 路径只是漏了）。再加一层自愈兜底：连续记录边界失败达阈值即强制重置，让任何未来新增的漏点也能在 ~30s 内恢复。

**Tech Stack:** Go 1.27，`chacha20poly1305`/`ecdh.X25519`+`hkdf`（现有 `internal/host/secure.go`）、`smux`、stock tailscale derper v1.102.3、`gost/x` 的 p2p host 库。

**Spec:** 证据与根因见 `wisper/docs/tun-hub-bandwidth-e2e.md`（受控 e2e 实锤）与 `go-gost/.memory/notes/p2p-relay-rebuild-secure-poison.md`（生产现场对照）。本计划是那份 e2e 报告"修复应从两处入手"中第 ② 项（状态清理）的落地；① datagram link 意外终止的根因仍未知，本计划只交付它的可观测性与"起爆后能自愈"的兜底（见 Task 3/4 的边界说明）。

## 背景与已确认事实（实现者不必重新推导）

- 记录格式 `[4B big-endian 长度][ciphertext+tag]`，收方向逐记录消耗 `recvCtr`（`internal/host/secure.go:81-86,163-185`）。
- `secureSession` 按 `(peer, transport)` 缓存，注释明确声称"比任何一条 mux 会话活得久，重建时复用同一密钥与 nonce 计数，单侧重建是透明的"（`secure.go:192-198`）——**这条假设只在"底层字节流连续且零丢失"时成立，而 relay 底层是逐包 DERP SendPacket（`engine.go:1606` `peerConn.Write`），本地杀会话会遗弃已读记录**。
- 现有正确先例：`dropRelaySecure`（`engine.go:821-839`），注释已写明"本地 kill 遗弃适配器里排队的记录 → nonce 已花但对端永不消费 → 必须重新握手"。它已挂在 relay 链路丢失（`engine.go:1230,1285`）与入站队列溢出/构建失败（`engine.go:950,965`）上。
- **漏点（生产 15s 循环的成因）**：会话因 smux keepalive 超时饿死、或经 `pc.kill(...)` 的其余路径被替换时，relay 安全会话被复用 → 新会话首记录即错位。`pc.kill` 调用点：`engine.go:725`（peer gone 探测超时，**无 drop**）、`1080`（peer rekeyed，**有意不 drop**）、`1240`（peer gone，**无 drop**）、`1639`（adapter closed，**无 drop**）、`1326`（engine closed，无所谓）。
- 生产对照：hub 侧 `secure record auth failed peer=zRiIjY4a…` 69 次、~15-17s 节奏、01:25:47Z→03:48:15Z，止于该 peer 切 direct；`p2p: bad secure record length 3559037810` 4 次（01:25:24×2 起、04:22:10 仍在）。direct 路径不受影响，因为 `rekeyIfUsed`（`secure.go:382-418`）每次打洞都换密钥与计数器。
- 决定：relay 重建时重新握手是安全的，且双端同时重建会在一次交换内收敛（`rekeyIfUsed` 注释已论证此收敛性）。代价是失败路径上多一个亚秒级控制往返。

## Global Constraints

- 绝不修改 `core/`；代码注释只用英文。
- 工作目录 `p2p/`（模块 `github.com/go-gost/p2p`）；门禁：`CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/...`，通配 `./...` 会挂。
- `go` 不在 PATH：`export PATH="$PATH:/root/.local/go/bin:/root/go/bin"`。
- `peer rekeyed` 路径（`resetPeerSession`）**禁止**加 drop：对端已换 half 且 `respond` 已重导出，计数器已对齐，再发一次新 half 会让两端互换（`engine.go:828-834` 的注释即此告诫）。
- 未获用户明确同意不得 commit/push（本计划每个 Task 末尾的提交步骤都需用户点头）。
- 与 `wisper/docs/superpowers/plans/2026-10-03-tun-hub-ip-allocation.md`（已全部落地）零代码重叠：那份只碰 `x/handler/tun` 与 `wisper/tunnel`，不碰 `p2p/internal/host/*`。唯一交集是 hub 侧 handler 的 `dropPeer` 路由回收语义——不要改它。

## Review Focus

以下输入/情形规格没写、但代码一旦这样跑就会咬人；每条都在对应任务的步骤里有测试钉住：

1. **本地 kill 时适配器里还有排队记录** → 必须重新握手（否则新会话首记录错位）。Task 1。
2. **`peer rekeyed`** → 必须**不**重新握手（否则两端互相换 half、永不 settle）。Task 1。
3. **双端同时重建** → 一次交换内收敛，不得来回重握手。Task 1。
4. **连续错位**（记录边界失败）→ 30s 内自愈，且日志能区分"首次失败"与"已重置"。Task 2。
5. **IPv6-only / direct-only 配置** → 本改动不得影响 direct 路径的 `rekeyIfUsed` 行为与 `secureTransportDirect` 分键缓存。Task 1 的回归测试。
6. **队列溢出路径**（`engine.go:965`）已 drop，不能因新加的兜底二次 drop 导致握手风暴。Task 2。

---

### Task 1: relay 会话替换即重新握手（核心修复）

**Files:**
- Modify: `internal/host/engine.go`（`pc.kill` 及其调用点、`sessionLocked` 重建分支）
- Test: `internal/host/session_lock_test.go`（追加）、`internal/host/secure_test.go`（追加）

**Interfaces:**
- Consumes: 既有 `func (e *engine) dropRelaySecure(peer derpclient.PublicKey)`（`engine.go:834`）、`func (pc *peerConn) kill(cause error)`（`engine.go:1561`）、`type peerConn` 上的 `transport byte`/会话字段。
- Produces: `func (pc *peerConn) killSession(cause error, dropSecure bool)`——`kill` 的显式化版本，`dropSecure=false` 仅用于 `resetPeerSession`（peer rekeyed）。既有 `kill(cause)` 调用点全部改为 `killSession(cause, true)`，唯 `engine.go:1080` 用 `killSession(cause, false)`。

- [ ] **Step 1: 写失败测试（本地 kill 遗弃排队记录 → 重建必须重新握手）**

在 `internal/host/session_lock_test.go` 追加 `TestRelaySessionReplaceRehandshakes`：
用现有 session_lock 测试的建对手法（参考 `TestSessionLockedReusesAfterTeardown` 之类既有 helper，勿自造 net.Pipe 装配）。场景：让 peer A、B 建立 relay 会话并互发数据；在 `pc.inbound` 预置一个包（模拟"杀会话时仍有排队记录"）；对 A 侧调用 `pc.kill(errors.New("test: local kill"))`；再 `ensureSession`。断言：新的 `pc.secure` 与旧的**不是同一指针**（`e.secure[secureKey{peer, secureTransportRelay}]` 被删除后重建），且 A、B 在 `handshakeTimeout` 内重新 settle 并能互发数据（断言字节往返成功）。

- [ ] **Step 2: 跑测试确认失败**

Run: `cd /root/code/go-gost/p2p && export PATH="$PATH:/root/.local/go/bin" && CGO_ENABLED=1 go test -race -count=1 -run TestRelaySessionReplaceRehandshakes ./internal/host/`
Expected: FAIL——旧 secure 会话被复用，指针相同 / 数据不通。

- [ ] **Step 3: 实现 `killSession` 并把漏点接上**

在 `engine.go` 中：
1. 新增 `func (pc *peerConn) killSession(cause error, dropSecure bool)`：原 `kill` 的实现体前插 `if dropSecure && pc.e != nil && pc.transport == secureTransportRelay { pc.e.dropRelaySecure(pc.peer) }`；保留 `kill(cause)` 作为 `killSession(cause, true)` 的薄封装（保留是为了不扩散签名改动，但**所有生产调用点都要显式化**）。
2. 调用点改为显式：`725`、`1240`、`1639` → `killSession(cause, true)`；`1080` → `killSession(cause, false)` 并就地加一行英文注释引用 `engine.go:828-834` 的理由。
3. 在 `sessionLocked`（`engine.go:1465`）替换死会话的分支：若被替换的旧会话属于 relay 传输，调用 `e.dropRelaySecure(peer)`（覆盖"smux keepalive 超时饿死→重建"这条不经过 `pc.kill` 的路径——生产 15s 循环正是这条）。
4. `direct` 传输一律不加 drop（`rekeyIfUsed` 已负责）。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/`
Expected: PASS（含既有 direct/rekey、e2e-encryption、session_lock 全绿）。

- [ ] **Step 5: 提交（需用户点头）**

```bash
git add internal/host/engine.go internal/host/session_lock_test.go
git commit -m "fix(p2p): re-handshake relay secure session when the mux session is replaced"
```

---

### Task 2: 记录边界连续失败的强制自愈兜底

**Files:**
- Modify: `internal/host/secure.go`（`readRecord` 失败计数与回调）、`internal/host/engine.go`（计数阈值判定与重置）
- Test: `internal/host/secure_test.go`（追加）

**Interfaces:**
- Consumes: `func (s *secureSession) conn(underlay net.Conn) (net.Conn, error)`（`secure.go:447`）、`secureSession` 上已有的 `mu`。
- Produces: `type secureSession` 新增字段 `desyncStreak int`、回调字段 `onDesync func(streak int)`；新方法 `func (s *secureSession) noteDesync() int`（在 `mu` 下自增并返回新值）；新方法 `func (s *secureSession) clearDesync()`。engine 侧在 `readRecord` 的两个错误分支调用 `noteDesync()`，达到阈值 `secureDesyncThreshold = 3` 时调用 `onDesync`。

- [ ] **Step 1: 写失败测试**

`internal/host/secure_test.go` 追加 `TestSecureDesyncStreakCounts`：构造一个 `secureSession` 与一条喂垃圾字节的 underlay（长度前缀为随机大数的记录），连续三次调用其 cryptoConn 的 `Read`，断言 `noteDesync()` 返回 1、2、3；`clearDesync()` 后再返回 1。再加 `TestBadRecordLengthStaysFatal`：`readRecord` 遇 `n > maxSecureRecord+16` 仍返回 `p2p: bad secure record length`（不得被兜底吞掉）。再加 `TestDesyncStreakNotInheritedByFreshSession`（钉住 Review Focus 第 6 条）：触发一次 `onDesync` 并让 `killSession(…, true)` 跑完后，新建的 relay `secureSession` 的 `desyncStreak` 必须为 0——队列溢出路径（`engine.go:950,965`）已 drop 过，兜底不得对同一次故障二次重置、否则升级成握手风暴。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -count=1 -run 'TestSecureDesyncStreak|TestBadRecordLength' ./internal/host/`
Expected: FAIL——`noteDesync` 未定义。

- [ ] **Step 3: 实现兜底**

1. `secure.go`：`secureSession` 加 `desyncStreak int` + `noteDesync()`/`clearDesync()`（都在既有 `s.mu` 下）。
2. `secure.go:170` 与 `180-182` 的失败分支：在返回错误前 `if n := s.noteDesync(); n >= secureDesyncThreshold && s.onDesync != nil { go s.onDesync(n) }`。`onDesync` **不**在 `secureSessionLocked` 里注入（该函数只拿到 peer 与 transport，够不着 `peerConn`）：赋值点定在 `engine.go:864` 构造 `peerConn` 字面量之后的那一行——`pc.secure.onDesync = func(n int) { e.log.Warn("p2p: relay secure desync, resetting", "peer", keyName(pc.peer), "streak", n); e.dropRelaySecure(pc.peer); pc.killSession(errors.New("p2p: secure desync"), true) }`；direct 传输的 `secureSession`（`engine.go:221`）**不设**该回调（直连靠 `rekeyIfUsed` 自愈，兜底只服务 relay）。回调以 `go` 派发，绝不可在持 `s.mu` 或 `e.mu` 时调用 `dropRelaySecure`/`killSession`（既有先例：`killSession` 内部取 `e.mu`）。
3. 会话成功读到一个记录（`readRecord` 成功路径）时 `clearDesync()`。
4. engine 收到通知的日志：`e.log.Warn("p2p: relay secure desync, resetting", "peer", keyName(peer), "streak", n)`——供现场一条日志定位。

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/`
Expected: PASS。

- [ ] **Step 5: 提交（需用户点头）**

```bash
git commit -am "fix(p2p): force secure re-handshake after repeated record-boundary failures"
```

---

### Task 3: 会话死亡/重建原因的结构化日志（为 datagram link 未知根因留证据）

**Files:**
- Modify: `internal/host/engine.go`（`sessionLocked`、`killSession`、pump 重启循环的日志字段）
- Test: 无新增单测（日志改动，靠 Task 1/2 的测试不回归保证）

**Interfaces:**
- Consumes: `pc.sessAt`、`killSession(cause, dropSecure)`、既有 `e.log.Debug("peer session killed", …)`（`engine.go:1561` 附近）。
- Produces: 统一日志字段 `relayReason`（会话重建原因字符串：`peer-gone-probe` / `local-kill` / `queue-overflow` / `link-lost` / `peer-rekeyed`）、`secureReuse`（bool：本次重建是否复用了 secure 会话）、`desyncStreak`。字段名在 Task 1/2 的日志里也统一使用。

- [ ] **Step 1: 在 `killSession` 补齐原因与 secure 处置**

`killSession` 内 `e.log.Debug("peer session killed", "peer", keyName(pc.peer), "cause", cause, "relayReason", reason, "dropSecure", dropSecure)`；`reason` 由调用点传入（给 `killSession` 加一个 `reason string` 参数，或定义 `type sessionEndReason string` 常量集——选后者，字段值才可被日志聚合）。

- [ ] **Step 2: 在 `sessionLocked` 重建分支记录 `secureReuse`**

重建前后比较旧/新 `pc.secure` 指针，输出 `e.log.Debug("relay session rebuilt", "peer", …, "secureReuse", reused, "sessionAge", age)`。

- [ ] **Step 3: 门禁**

Run: `CGO_ENABLED=1 go test -race -count=1 -p 1 ./internal/host/ && go vet ./internal/host/`
Expected: PASS / 无输出。

- [ ] **Step 4: 提交（需用户点头）**

```bash
git commit -am "chore(p2p): structured session-death and rebuild reasons in logs"
```

---

### Task 4: e2e 回归——故障注入后必须恢复且持续吞吐 > 0

**Files:**
- Modify: `wisper/scripts/perf-tun-hub.sh`（新增 `--inject-session-kill` 档位：稳态传输中周期性打断会话）
- Modify: `wisper/docs/tun-hub-bandwidth-e2e.md`（追加"修复后复测"小节，记录新数字与恢复耗时）
- Test: 该脚本自身即测试（需 root + `/dev/net/tun` + docker + `gogost/derper`）

**Interfaces:**
- Consumes: 既有 `scripts/perf-tun-hub.sh` 的 hub/spoke 装配与 iperf3 度量；`p2p` 的 fault 注入（`internal/host/faults.go`，`muteData` 等，勿新增注入通道）。
- Produces: 脚本退出码语义：`0`=持续吞吐达标且注入后恢复；`2`=恢复但吞吐不达标；`1`=未恢复（15s 循环复现）。

- [ ] **Step 1: 脚本加注入档位**

`--inject-session-kill` 每 20s 杀一次 hub 侧会话（复用 Task 3 的日志字段判定"已重建"），继续 iperf3 `-t 60`；脚本在结束后 grep hub 日志：有 `secureReuse=true` 且无 `bad secure record length` 记 PASS。

- [ ] **Step 2: 跑一次修复前基线（可选但推荐，用于确认脚本真的能复现）**

Run: `cd /root/code/go-gost/wisper && ./scripts/perf-tun-hub.sh /tmp/wisper-tun-perf-inj --inject-session-kill`
Expected（修复前）: 退出码 1，日志出现 `bad secure record length`。

- [ ] **Step 3: 修复后跑同一档位**

Expected: 退出码 0；报告中记下恢复耗时（目标：单次重建 < 2s，全程无 15s 级循环）与持续吞吐数字。

- [ ] **Step 4: 更新报告文档**

在 `tun-hub-bandwidth-e2e.md` 追加"修复后复测"小节：注入档位结果、恢复耗时、持续吞吐；并注明 ping-only 的 `smoke-tun.sh` 为何不足以作为回归门禁（保留教训）。

- [ ] **Step 5: 提交（需用户点头）**

```bash
cd wisper && git add scripts/perf-tun-hub.sh docs/tun-hub-bandwidth-e2e.md && git commit -m "test(wisper): e2e regression for relay session rebuild recovery"
```

---

## 明确不做（本轮）

- 不定位 datagram link 意外终止的根因（Task 3 只留证据；修复后它退化为可自愈的抖动，不再是永久中断）。
- 不改 derper 侧任何行为（`lastWriterIsActive` 重复连接策略经生产证据已排除为本次根因，无需动）。
- 不改 smux 参数、不改 3s/15s keepalive（15s 是症状的时钟，不是病因）。
- 不动 `x/`（`x` 侧下一版 v0.20.0 由 IP 分配计划占用，本计划不与之竞争发布窗口）。