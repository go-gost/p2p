# p2p NAT 形状诊断（S1+S2）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 p2p 已经在计算的两个 NAT 形状事实（对端从非通告端点应答 / 直连只发不收），变成 per-peer 的一句人话结论 `NATShape`，在进程内的 doctor（wisper 的 `/api/p2p/doctor`）里可见。

**Architecture:** 纯诊断，零行为变更。F1 在 seed 握手成功后判定：应答端点 ∉ 对端本轮通告的候选集合（比较走 `sameAddrPort`，以 unmarshal v4-in-v6）。F2 复用既有的 `directOneWayDead`，但新增"latch 归属于当前 underlay"的判别，避免对着已退役的路径报时长。两个事实经一个纯函数查表成 `NATShape`，装进 `p2p.PeerDiagnostic`（in-process only，proto 冻结），由 `p2p/doctor` 渲染。**不改 wire、不改配置、不改打洞决策、不扩 proto、不加依赖。**

**Tech Stack:** Go 1.26.4（`p2p/go.mod`）；标准库 only；无新依赖。

**Spec:** `p2p/docs/superpowers/specs/2026-10-21-p2p-nat-shape-diagnosis-design.md`
（计划与 spec 的分歧只有一处，已在 Task 1 Step 4 标出：F1 观测的"最近一次成功轮次"语义 —— **最新一次观测整体覆盖前一次，匹配与不匹配一视同仁**。）

## Global Constraints

- 只改 `p2p/` 模块内的文件。**不改 `core/`、不改 `plugin/`**（gRPC proto 冻结，`p2p/status.go` 多处注明 "in-process only: the gRPC transport's proto is frozen"）。
- 注释只写英文（[[english-only-comments]]）。
- trace 文本是 API：只允许**新增**行，不许改现有行（[[wisper-peer-row-rtt-order-trace-times]]：`lastBackoffWait` 切 `backoff ` 前缀 + `ParseDuration`）。
- `PeerDiagnostic.PeerAddr` 的语义保持"对端应答的端点"（`markUp(sock, answer, token)` 注册的就是它）；本轮**只修它的过时注释**，不改语义。
- Go 工具链不在非登录 shell 的 PATH 上 ⇒ 所有 `go` 命令用 `bash -lc` 包一层。
- 本机通配 `go test ./...` 会挂住 ⇒ **逐包跑**（[[go-test-wildcard-hangs]]）：`go test ./internal/host/ -count=1`、`go test ./doctor/ -count=1`、`go test . -count=1`。
- `p2p` 是独立 git 仓库 ⇒ git 命令在 `p2p/` 目录里执行（或 `git -C p2p`）。
- **不要自动 commit / push**（[[no-auto-commit]]）：本计划里的 commit 步骤**只在用户明确要求时**执行。

## Review Focus

1. **v4-in-v6**：`::ffff:a.b.c.d` 与 `a.b.c.d` 必须判为同一端点，否则每次健康的 v4 直连都会被误报成 per-destination。→ Task 1 `TestContainsAddr`
2. **hairpin（同一 NAT 的双方）**：我们按 hairpin 规则拨对端的**本地**地址、它从**公网**地址应答 ⇒ 公网地址**在**通告集合里 ⇒ 不得判为 F1。→ Task 1 `TestContainsAddr`
3. **跨族比较**：F1 只能拿**本轮所拨族**的通告集合比对（v4 的应答不能与 v6 候选比）。→ Task 1 `TestNotePeerEndpointComparesWithinOneFamily`
4. **陈旧 latch**：一条被换掉的直连留下的 one-way latch，不得让新路径报时长。→ Task 2 `TestDirectOneWayForIgnoresStaleUnderlay`
5. **wire 调用方**：doctor 不得对没测到的字段宣称零值，必须说 "not reported by the control plane"。→ Task 4 `TestReportSaysNATShapeNotReportedOverWire`

---

### Task 1: F1 —— 分类器、记录与接入打洞轮次

**Files:**
- Modify: `p2p/internal/host/direct.go`
- Test: `p2p/internal/host/direct_nat_test.go`（新建）

**Interfaces:**
- Consumes: `sameAddrPort(a, b netip.AddrPort) bool`（`internal/host/directunderlay.go:282`）、`candidate{addr netip.AddrPort}`（`direct.go:183`）、`ipv4Addrs(cands []candidate) []netip.AddrPort`（`direct.go:1555`）、`v6Addrs(cands []candidate) []netip.AddrPort`（`direct.go:1568`）、`dc.noteRound(format string, args ...any)`（`direct.go:627`）
- Produces:
  - `func containsAddr(list []netip.AddrPort, addr netip.AddrPort) bool`
  - `func (dc *directConn) notePeerEndpoint(answered netip.AddrPort, announced []netip.AddrPort)`
  - `func (dc *directConn) natEndpoint() (differs bool, answered netip.AddrPort, observedAt time.Time)`
  - `directConn` 新字段（全部受 `dc.mu` 保护）：`peerEndpointDiffers bool`、`peerAnsweredFrom netip.AddrPort`、`peerEndpointObservedAt time.Time`

- [ ] **Step 1: 写失败测试 `TestContainsAddr`**

  在 `p2p/internal/host/direct_nat_test.go` 新建文件，`package host`。表驱动，四例：
  - 端点在集合内 ⇒ true
  - 端点不在集合内（集合只有另一个端口）⇒ false
  - 集合里是 `::ffff:203.0.113.9:51000`、被查的是 `203.0.113.9:51000` ⇒ **true**（v4-in-v6 等价）
  - **hairpin 形状** ⇒ true：通告集合是 `{203.0.113.4:3478（对端本地）, 198.51.100.7:62000（对端公网）}`，被查的是 `198.51.100.7:62000` —— 同 NAT 的双方按 hairpin 规则拨对端的**本地**地址、它从**公网**地址应答，公网地址在通告集合里 ⇒ 不是 F1
  - 空集合 ⇒ false

- [ ] **Step 2: 跑测试确认失败**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestContainsAddr -count=1"`
  期望：编译失败 `undefined: containsAddr`。

- [ ] **Step 3: 实现 `containsAddr`**

  放在 `internal/host/direct.go` 里 `ipv4Addrs`/`v6Addrs` 之后（`direct.go:1578` 附近）。逐个元素用 `sameAddrPort` 比较，命中即 true。注释写明它 unmarshal v4-in-v6（否则每次健康的 v4 直连都会被误判）。

- [ ] **Step 4: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestContainsAddr -count=1"` ⇒ PASS。

- [ ] **Step 5: 写失败测试 `TestNotePeerEndpointRecordsMismatch` / `...KeepsMatch` / `...OverwritesPrevious`**

  直接构造 `dc := &directConn{}`（同包，可直接 new）：
  - 传入 `answered = 203.0.113.9:51000`、`announced = []netip.AddrPort{203.0.113.4:3478}` ⇒ `natEndpoint()` 返回 `differs == true`、`answered == 203.0.113.9:51000`、`observedAt` 非零。
  - 传入 `answered` 在 `announced` 里 ⇒ `differs == false`。
  - 先记一次 mismatch、再记一次 match ⇒ 第二次之后 `differs == false` 且 `observedAt` 比第一次**更新**（最新一次观测整体覆盖前一次）。

- [ ] **Step 6: 跑测试确认失败**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestNotePeerEndpoint -count=1"` ⇒ 编译失败（undefined: notePeerEndpoint / natEndpoint）。

- [ ] **Step 7: 实现记录与读取**

  `directConn` 里加三个字段（放在 `peerAddr` 附近，`direct.go:210` 一带），并加锁注释（"Guarded by mu like the rest of the round's state"）。

  `notePeerEndpoint(answered, announced)`：
  1. `differs := !containsAddr(announced, answered)`
  2. 在 `dc.mu` 内写 `dc.peerEndpointDiffers = differs`、`dc.peerAnsweredFrom = answered`、`dc.peerEndpointObservedAt = time.Now()`，**释放锁**
  3. `differs` 为真时**在锁外**调 `dc.noteRound("peer answered from %s (not announced)", answered)` —— `noteRound` 自己拿 `dc.mu`，在锁内调会死锁。

  `natEndpoint()`：在 `dc.mu` 内读三个字段并返回。

  注释里写清：观测取**最近一次成功的 seed**，失败的轮次没有观测、不清除旧值（sticky：读者要问的正是"这个 peer 为什么还在 relay 上"）。

- [ ] **Step 8: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run 'TestContainsAddr|TestNotePeerEndpoint' -count=1"` ⇒ PASS。

- [ ] **Step 9: 写失败测试 `TestNotePeerEndpointTracesMismatch` / `TestNotePeerEndpointComparesWithinOneFamily`**

  - trace：`dc.notePeerEndpoint(未通告端点, ...)` 之后，`dc.traceSnapshot()` 的行里**必须**出现 `peer answered from 203.0.113.9:51000 (not announced)`；匹配时**不得**出现 `not announced`。
  - 跨族：`announced` 只给 v6 候选、answered 给 v4 ⇒ 判为 mismatch（v4 不在 v6 集合里）；断言这一点是为了钉住"只与本轮所拨族比对"的用法（真正的族隔离在调用点做，见 Step 11）。

- [ ] **Step 10: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run 'TestNotePeerEndpoint' -count=1"` ⇒ PASS（Step 9 的 trace 行已在 Step 7 实现，若失败则补上）。

- [ ] **Step 11: 接入打洞轮次**

  在 `internal/host/direct.go:1366` 的 `token, answer, err := seedHandshakeUDPToken(f.sock, dial, seedTimeout)` 成功之后、`dc.markUp(sock, answer, token)`（`:1390`）之前，按**本轮所拨族**取通告集合并调用：

  ```go
  announced := peerV4
  if f.v6 {
      announced = peerV6
  }
  dc.notePeerEndpoint(answer, announced)
  ```

  （`peerV4`/`peerV6` 是 `:1307-1308` 已经算好的本轮通告列表，取的是最新鲜那份。）

- [ ] **Step 12: 顺手修 `peerAddrString` 的过时注释**

  `internal/host/direct.go:971` 的注释写着 "the peer's **dialed** endpoint"，实际是 `markUp` 传入的**应答端点**。改成应答端点，并说明它就是 peer block 里 "peer addr" 那一行。**只改注释，不改行为。**

- [ ] **Step 13: 跑整包测试确认无回归**

  `bash -lc "cd p2p && go test ./internal/host/ -count=1"` ⇒ 与改动前同绿（该包的 direct/fault 测试按 run 数统计 flaky，见 [[p2p-link-sessionscoped-tun-coupling]]；若某个 direct/fault 用例红了，用 `git stash` 对照基线确认与本次改动无关）。

- [ ] **Step 14: commit（仅在用户明确要求时）**

  ```bash
  git -C p2p add internal/host/direct.go internal/host/direct_nat_test.go
  git -C p2p commit -m "feat(p2p): record the peer's answering endpoint vs what it announced"
  ```

---

### Task 2: F2 —— one-way latch 的归属与读法

**Files:**
- Modify: `p2p/internal/host/relaykcp.go`、`p2p/internal/host/direct_oneway_test.go`
- Test: `p2p/internal/host/direct_oneway_test.go`（扩写）

**Interfaces:**
- Consumes: `relayKCPPair.direct *directUnderlay`（`relaykcp.go` 的 `setDirectUnderlay`）、`relayKCPPair.oneWayAt time.Time`（`relaykcp.go:297`，受 `p.mu` 保护）
- Produces:
  - `func (p *relayKCPPair) directOneWayDead(now time.Time, u *directUnderlay) bool` —— **签名变了**（多一个 underlay 参数）
  - `func (p *relayKCPPair) directOneWayFor(now time.Time) time.Duration` —— 0 = 不是单向，或 latch 不属于当前 underlay
  - `relayKCPPair` 新字段 `oneWayU *directUnderlay`（受 `p.mu` 保护）

- [ ] **Step 1: 改 `directOneWayDead` 的签名，并在 latch 时记下 underlay**

  `internal/host/relaykcp.go:968`：

  ```go
  func (p *relayKCPPair) directOneWayDead(now time.Time, u *directUnderlay) bool {
  ```

  在 latch 分支（`relaykcp.go:989-991`，即 `if p.oneWayAt.IsZero() { p.oneWayAt = now }`）里同时记 `p.oneWayU = u`。加注释说明为什么记：换掉一条因单向被判死的直连之后，latch 仍带着旧时间戳，若不记归属，新装的 underlay 会对着陈旧 latch 重新 latch（`now.Sub(oneWayAt) >= window` 立刻为真）——**这是既有隐患，本轮只在读法上规避，不改行为**（见 Task 5 的 README/记忆条目与 spec §10.0）。

  生产调用点 `relaykcp.go:1032` 改为 `p.directOneWayDead(time.Now(), u)`（`u` 是 `pumpDirect` 的参数）。

- [ ] **Step 2: 改既有 5 处测试调用点，跑测试确认无回归**

  `internal/host/direct_oneway_test.go` 的 `:44 :62 :84 :103 :114` 改成 `pair.directOneWayDead(now, nil)`。传 nil 表示"不归属任何 underlay"，形状判定逻辑不变（这 5 个用例只断言 bool）。

  `bash -lc "cd p2p && go test ./internal/host/ -run TestDirectOneWay -count=1"` ⇒ PASS。

  ⇒ 顺序：先改生产签名（Step 1）再改测试调用点，然后跑。

- [ ] **Step 3: 写失败测试 `TestDirectOneWayForAttributesToLiveUnderlay`**

  `pair := &relayKCPPair{}`；`u := &directUnderlay{}`；`pair.direct = u`（同包可直接赋值）。把 `directOneWayWindow` 临时改小（沿用既有测试的 `defer func(w time.Duration) { directOneWayWindow = w }(directOneWayWindow)` 写法）。喂单向流量（只加 `directBytesSent`）直到 latch 成立，然后断言 `pair.directOneWayFor(now) > 0`。

- [ ] **Step 4: 写失败测试 `TestDirectOneWayForIgnoresStaleUnderlay`**

  同上构造并让 latch 成立，然后**把 `pair.direct` 换成另一个 underlay 指针**，断言 `pair.directOneWayFor(now) == 0`（陈旧 latch 不得让新路径报时长）。

- [ ] **Step 5: 跑测试确认失败**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestDirectOneWayFor -count=1"` ⇒ 编译失败 `undefined: directOneWayFor`。

- [ ] **Step 6: 实现 `directOneWayFor`**

  ```go
  func (p *relayKCPPair) directOneWayFor(now time.Time) time.Duration {
      p.mu.Lock()
      defer p.mu.Unlock()
      if p.oneWayU == nil || p.oneWayU != p.direct || p.oneWayAt.IsZero() {
          return 0
      }
      return now.Sub(p.oneWayAt)
  }
  ```

  注释写清：只有当 latch 属于**当前** underlay 时才报时长；否则宁可不说，也不对着一条已退役的路径说"已经单向 N 分钟"。

- [ ] **Step 7: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run 'TestDirectOneWay' -count=1"` ⇒ PASS。

- [ ] **Step 8: 跑整包测试确认无回归**

  `bash -lc "cd p2p && go test ./internal/host/ -count=1"` ⇒ 无回归。

- [ ] **Step 9: commit（仅在用户明确要求时）**

  ```bash
  git -C p2p add internal/host/relaykcp.go internal/host/direct_oneway_test.go
  git -C p2p commit -m "feat(p2p): attribute the one-way latch to the underlay that latched it"
  ```

---

### Task 3: pair 级结论词装配

**Files:**
- Modify: `p2p/status.go`、`p2p/internal/host/engine.go`
- Create: `p2p/internal/host/natshape.go`
- Test: `p2p/internal/host/natshape_test.go`（新建）、`p2p/internal/host/natdiag_test.go`（新建）

**Interfaces:**
- Consumes: `dc.natEndpoint() (differs bool, answered netip.AddrPort, observedAt time.Time)`（Task 1）、`pair.directOneWayFor(now) time.Duration`（Task 2）、`e.relayKCPPairGet(peer) *relayKCPPair`（`engine.go`）
- Produces:
  - `p2p.PeerDiagnostic.NATShape string` —— `""` / `"one-way"` / `"peer-endpoint-differs"` / `"one-way+peer-endpoint-differs"`
  - `p2p.PeerDiagnostic.NATObservedAge time.Duration`
  - `p2p.PeerDiagnostic.OneWayFor time.Duration`
  - `func natShape(differs bool, oneWay time.Duration) string`（`internal/host/natshape.go`）

- [ ] **Step 1: 写失败测试 `TestNatShape`**

  `p2p/internal/host/natshape_test.go`，`package host`。四个用例断言**精确值**：
  - `natShape(false, 0)` ⇒ `""`
  - `natShape(true, 0)` ⇒ `"peer-endpoint-differs"`
  - `natShape(false, 3*time.Minute)` ⇒ `"one-way"`
  - `natShape(true, 3*time.Minute)` ⇒ `"one-way+peer-endpoint-differs"`

- [ ] **Step 2: 跑测试确认失败**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestNatShape -count=1"` ⇒ 编译失败 `undefined: natShape`。

- [ ] **Step 3: 实现 `natShape`**

  新建 `p2p/internal/host/natshape.go`（`package host`）。**查表**（四种组合），不是优先级级联。注释写清每个值的**证据**是什么，以及 `peer-endpoint-differs` **不蕴含**"打不通"（learned 地址机制正是为此而生）。

- [ ] **Step 4: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run TestNatShape -count=1"` ⇒ PASS。

- [ ] **Step 5: 给 `PeerDiagnostic` 加三个字段**

  `p2p/status.go` 的 `PeerDiagnostic` 里加：

  ```go
  // NATShape is the pair's NAT-shape verdict: "" (not observed),
  // "one-way", "peer-endpoint-differs" or "one-way+peer-endpoint-differs".
  NATShape string
  // NATObservedAge is how long ago the latest seed observation was made ...
  NATObservedAge time.Duration
  // OneWayFor is how long the current direct underlay has been one-way ...
  OneWayFor time.Duration
  ```

  注释里写明：结论词背后的**证据**、以及为什么它**不是**"要不要打洞"的判据（纯诊断）。字段是 in-process only（proto 冻结）。

  同时**修 `p2p/status.go:22` 的过时注释**：`PeerAddr` 写的是 "the endpoint **dialled** for the direct path"，实际是**对端应答的端点**（`markUp(sock, answer, token)` 注册的就是它）。只改注释。

- [ ] **Step 6: 在 engine 里填三个字段**

  `p2p/internal/host/engine.go` 的 `directs` 循环（`engine.go:327-358`）里，取 `pair := e.relayKCPPairGet(dc.peer)`（`fillPairDiag` 已经在拿它，`engine.go:367`），然后：

  ```go
  d.OneWayFor = 0
  if pair != nil {
      d.OneWayFor = pair.directOneWayFor(now)
  }
  differs, _, at := dc.natEndpoint()
  if !at.IsZero() {
      d.NATObservedAge = now.Sub(at)
  }
  d.NATShape = natShape(differs, d.OneWayFor)
  ```

  `now` 已在该函数里取好（`engine.go:292`）。

- [ ] **Step 7: 写失败测试 `TestPeerDiagnosticsCarryNATShape`**

  `p2p/internal/host/natdiag_test.go`，`package host`。**照抄 `internal/host/pairdiag_test.go:105-150` 的构造法**：

  ```go
  priv, _, err := derpclient.Generate()
  e := newEngine("", "", priv, slog.New(slog.NewTextHandler(io.Discard, nil)))
  t.Cleanup(e.Close)
  peer := derpclient.PublicKey{62}
  dc := e.directConn(peer)                                  // 建 directConn（direct.go:296，会挂进 e.directs）
  pair := e.relayKCPPairFor(peer)                           // engine.go:1230
  t.Cleanup(pair.shutdown)
  u := pairUnderlay(t, pair)                                // pairdiag_test.go:38 的既有助手，装上并返回 underlay
  ```

  然后：
  1. `dc.notePeerEndpoint(netip.MustParseAddrPort("203.0.113.9:51000"), []netip.AddrPort{netip.MustParseAddrPort("203.0.113.4:3478")})` ⇒ F1 成立。
  2. 喂单向流量（`pair.directBytesSent.Add(1024)`）并反复调 `pair.directOneWayDead(now, u)`，直到 latch 成立（`directOneWayWindow` 临时改小，沿用 `direct_oneway_test.go` 的 `defer` 还原写法）⇒ `pair.directOneWayFor(now) > 0`。
  3. 装配诊断：`out := e.peerDiagnostics(map[string]string{keyName(peer): "derp"})` —— `peerDiagnostics` 收 transports 表作为参数（`engine.go:268`），所以测试**不需要**真的建出会话；`keyName` 是 host 包内既有助手。
  4. 取 `d := out[keyName(peer)]`，断言：`d.NATShape == "one-way+peer-endpoint-differs"`、`d.NATObservedAge > 0`、`d.OneWayFor > 0`。

- [ ] **Step 8: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./internal/host/ -run 'TestNatShape|TestPeerDiagnosticsCarryNATShape' -count=1"` ⇒ PASS。

- [ ] **Step 9: 跑整包与根包测试**

  `bash -lc "cd p2p && go test ./internal/host/ -count=1"`、`bash -lc "cd p2p && go test . -count=1"` ⇒ 无回归。

- [ ] **Step 10: commit（仅在用户明确要求时）**

  ```bash
  git -C p2p add status.go internal/host/engine.go internal/host/natshape.go internal/host/natshape_test.go internal/host/natdiag_test.go
  git -C p2p commit -m "feat(p2p): report a per-peer NAT shape verdict"
  ```

---

### Task 4: doctor 输出

**Files:**
- Modify: `p2p/doctor/doctor.go`
- Test: `p2p/doctor/doctor_test.go`

**Interfaces:**
- Consumes: `p2p.PeerDiagnostic.NATShape / NATObservedAge / OneWayFor / PeerAddr`（Task 3）、`doctor.Options.InProcess`（`doctor.go:50`）、`doctor.peerKeys(st, opts.Peer)`（`doctor.go` 既有）
- Produces: doctor 报告里的
  - peer block 的一行 `nat shape`（仅当 `NATShape != ""`）
  - peer verdict 追加的 NAT 短语
  - host 级汇总行 `NAT shape: <n> of <m> observed peers show a per-destination endpoint`
  - wire 调用方的 `NAT shape: not reported by the control plane`

- [ ] **Step 1: 写失败测试 `TestPeerBlockShowsNATShape`**

  `p2p/doctor/doctor_test.go`（`package doctor`）。构造一个 `p2p.Status`，其 `PeerDiagnostics` 里有一个 `PeerDiagnostic{NATShape: "peer-endpoint-differs", NATObservedAge: 2 * time.Minute, PeerAddr: "203.0.113.9:51000"}`；断言 `Report(st, Options{InProcess: true})` 的输出含 `nat shape`、含 `peer-endpoint-differs`、含 `203.0.113.9:51000`、含 `2m0s`。

- [ ] **Step 2: 写失败测试 `TestPeerVerdictNamesPeerEndpoint` 与 `TestPeerVerdictNamesOneWay`**

  - F1：断言输出含 `answers from 203.0.113.9:51000` 与 `did not announce`。
  - F2（`OneWayFor: 3 * time.Minute`，`NATShape: "one-way"`）：断言输出含 `one-way` 与 `3m0s`；并且断言输出**不含** `NAT`（单向是路径健康问题，不得被写成 NAT 结论）。

- [ ] **Step 3: 写失败测试 `TestReportSaysNATShapeNotReportedOverWire`**

  - `Report(st, Options{})`（`InProcess` 为 false）⇒ 输出含 `NAT shape: not reported by the control plane`。
  - `Report(st, Options{InProcess: true})` ⇒ 输出**不含**该句。
  （沿用 `relayRTT` 的既有纪律，`doctor.go:369`。）

- [ ] **Step 4: 跑测试确认失败**

  `bash -lc "cd p2p && go test ./doctor/ -run 'TestPeerBlockShowsNATShape|TestPeerVerdictNames|TestReportSaysNATShape' -count=1"` ⇒ 失败（输出里还没有这些内容）。

- [ ] **Step 5: 实现 peer block 的一行**

  `p2p/doctor/doctor.go` 的 `peerBlock`（`:192`）里，在 `peer addr` 那一行（`:216`）之后加：

  ```go
  if d.NATShape != "" {
      field(b, "    nat shape", natShapeDetail(d))
  }
  ```

  新增一个助手（放在 `doctor.go` 内，与 `peerVerdict` 同文件）：

  ```go
  // natShapeDetail renders the verdict and its evidence: which endpoint the
  // peer actually answered from, and how long the direct path has been one-way.
  func natShapeDetail(d p2p.PeerDiagnostic) string
  ```

  格式固定为：`<NATShape> (<part1>; <part2>)`，其中
  - F1 部分：`peer answers from <PeerAddr>, an endpoint it did not announce (observed <NATObservedAge> ago)`
  - F2 部分：`the direct path has been one-way for <OneWayFor> (we send, nothing comes back)`
  - 只有一个部分时不要分号。

  `PeerAddr` 为空时用 `orNone(d.PeerAddr)`（既有助手）。

- [ ] **Step 6: 实现 peer verdict 的短语**

  `peerVerdict`（`:324`）在 `direct` / `failed` / default 三个分支的既有句子后面追加 `" ; NAT shape: " + natShapeDetail(d)`（仅当 `d.NATShape != ""`；wire 调用方拿到的 `NATShape` 恒为空 ⇒ 不会追加）。

- [ ] **Step 7: 实现 host 级汇总行**

  `verdicts`（`:249`）里：

  - `!opts.InProcess` ⇒ 追加 `NAT shape: not reported by the control plane`。
  - 否则：用 `peerKeys(st, opts.Peer)` 取本轮要展示的 peer，统计 `m` = `NATShape != ""` 的 peer 数、`n` = 其中 `NATShape` 含 `peer-endpoint-differs` 的 peer 数；`m == 0` ⇒ **整行省略**；否则追加 `NAT shape: <n> of <m> observed peers show a per-destination endpoint`。

  措辞纪律：`one-way` **不得**出现在 host 汇总行里（它是路径健康，不是 NAT 形状）。

- [ ] **Step 8: 跑测试确认通过**

  `bash -lc "cd p2p && go test ./doctor/ -count=1"` ⇒ PASS。

- [ ] **Step 9: 跑根包测试（doctor 依赖 `p2p` 契约包）**

  `bash -lc "cd p2p && go test . -count=1"` ⇒ 无回归。

- [ ] **Step 10: commit（仅在用户明确要求时）**

  ```bash
  git -C p2p add doctor/doctor.go doctor/doctor_test.go
  git -C p2p commit -m "feat(p2p): show the NAT shape verdict in the doctor report"
  ```

---

### Task 5: e2e 反向断言、README、记忆

**Files:**
- Modify: `p2p/tests/e2e/run.sh`
- Modify: `p2p/README.md`
- Modify: `.memory/notes/p2p-nat-type-detection-eval.md`、`.memory/MEMORY.md`（工作区根，不在 p2p 仓库里）

**Interfaces:**
- Consumes: e2e helper 已经把 `peer_diagnostics` 整体 JSON 化（`p2p/tests/e2e/helper/main.go:96`）⇒ trace 行在 `status.json` 里；`check_grep` 是 run.sh 既有的断言助手
- Produces: 无新接口

- [ ] **Step 1: 加 e2e 反向断言**

  `p2p/tests/e2e/run.sh` 里，紧挨着既有的 `check_grep "status carries a per-peer diagnostic" '"peer_diagnostics":\[' "$dir/status.json"`（`:405`）加一条**否定**断言：

  ```bash
  if grep -q "not announced" "$dir/status.json"; then
      fail "a peer answered from an endpoint it did not announce, in a topology with no NAT"
  fi
  ```

  理由：e2e 拓扑是 netns + veth + bridge，**两侧同桥、无 masquerade** ⇒ 不可能产生 F1 ⇒ 这是一条真实的反向断言（trace 在 wire 上，所以可表达）。新字段本身 e2e 看不到（proto 冻结），**不要**写成对诊断字段的断言。

- [ ] **Step 2: 跑 e2e（需要 Docker）**

  `bash -lc "cd p2p/tests/e2e && ./run.sh"`（或按该目录 README 的跑法）。若本机跑不动（缺 Docker / 权限），记录"e2e 未跑"并继续；**不要**因为跑不动就把断言删掉。

- [ ] **Step 3: 更新 README 的 doctor 段落**

  `p2p/README.md` 的 doctor 段（`:475` 附近）加一句：NAT 形状结论（`NATShape`）是 **in-process only** —— `p2p doctor` CLI 走 gRPC、proto 冻结 ⇒ 看不到；wisper 的 `/api/p2p/doctor` 是进程内的 ⇒ 能看到；CLI 侧仍能在原始 trace 里看到 `peer answered from … (not announced)` 这一行。

- [ ] **Step 4: 更新记忆**

  `.memory/notes/p2p-nat-type-detection-eval.md`：把"A 档形态"一节改写成**实际落地的形态**（S1 = 应答端点 ∉ 通告集合；S2 = latch 归属当前 underlay；四组合查表；in-process only；doctor CLI 看不到），并记下"p2p 的 STUN 客户端只讲 tailnode 方言 ⇒ 公共 STUN 大概率不可用""单 DERP ⇒ 没有第二个 STUN 目的地"这两条已核实的事实。
  `.memory/MEMORY.md`：更新 `[[p2p-nat-type-detection-eval]]` 那一行。
  ⚠️ 记忆只写在**工作区根**的 `.memory/`，不写进 `p2p/`（那是有 upstream remote 的独立仓库）。

- [ ] **Step 5: 跑全部受影响的包**

  `bash -lc "cd p2p && go test ./internal/host/ -count=1"`、`bash -lc "cd p2p && go test ./doctor/ -count=1"`、`bash -lc "cd p2p && go test . -count=1"` ⇒ 全绿。
  （**不要**跑 `go test ./...` —— 本机会挂住。）

- [ ] **Step 6: commit（仅在用户明确要求时）**

  ```bash
  git -C p2p add tests/e2e/run.sh README.md
  git -C p2p commit -m "test(p2p): assert the e2e topology produces no NAT-shape mismatch"
  ```

  记忆文件在**工作区根**的另一个 git 仓库里 ⇒ 单独提交（同样只在用户要求时）。

---

## 附：不属于本轮的事（不要顺手做）

- 扩 gRPC proto 让 CLI 也能看到 `NATShape`（与"proto 冻结"冲突，需单独决策）。
- 修 `setDirectUnderlay` 不重置 `oneWayAt` 的既有隐患（新 underlay 可能首个 tick 即被判死）—— spec §10.0，**另立 issue**。
- "我方是 per-destination"的判定（需要对端回报它看到的源地址 ⇒ wire 变更）。
- host 级 NAT 标签（需要第二个 STUN 目的地）。
- 任何"用 `NATShape` 决定要不要打洞"的策略改动（本轮纯诊断）。
