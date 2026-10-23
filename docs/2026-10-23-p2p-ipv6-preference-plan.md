# p2p：v6 优先的并发换族打洞 + IPv6 opt-in —— 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让打洞的两个候选族（v6/v4）**同时**尝试、并按 v6 严格优先裁决，同时把 IPv6 变成一个默认关闭的 opt-in。

**Architecture:** 每族一个 socket、一个 `seedHandshakeUDPToken` 调用，在各自的 goroutine 里跑；裁决循环**先等 v6 的结果**，只有 v6 失败才采用（已在并行跑完的）v4 结果。赢家确定后关闭其余族的 socket 并等它们的 goroutine 退出，再走原有的 `markUp` 路径。IPv6 由 `Config.IPv6`（默认 false）门控：不开启就不探测、不收集、不发 capability 位。

**Tech Stack:** Go 1.26（`go.mod`）；`net`/`netip`；标准 `testing`；`-race`。

**Spec:** `docs/2026-10-23-p2p-ipv6-preference-design.md`

## Global Constraints

- 模块是独立仓库：所有命令在 `/root/code/go-gost/p2p` 下执行；测试用 `./internal/host/` 等具体包名（通配 `./...` 在本机不稳）。
- `seedHandshakeUDPToken(sock *net.UDPConn, peer netip.AddrPort, timeout time.Duration) (seedOutcome, error)` 的签名与线上格式**不得改动**。
- 生产默认值不得变：`punchTimeout = 10s`（direct.go:96）、`seedTimeout = 5s`（direct.go:141）、`seedRetransmit = 200ms`、`capsIPv6 = 1<<0`（direct.go:57）。
- 一轮只注册**一个** direct underlay；赢家的 socket 交给 `markUp`，其余必须关闭。
- 注释、提交信息、代码标识符用英文；设计/计划文档、与用户对话用中文。
- 任一步骤后必须 `gofmt -l .` 无输出、`go vet ./...` 通过。
- 不自动 `git commit` 之外的动作（不 push），除非用户明确要求。

## Review Focus

- **启动后才出现的 v6 出口**：开启后每轮都要重探，不能只在 `Connect` 探一次（否则 DAD 未完成/DHCPv6 晚到的机器永远用不上 v6）。
- **v6 关闭时对端仍在通告 v6**：我们绝不能因此去拨 v6（没有 v6 family 就不该有 v6 拨号）。
- **赢家确定后另一族的 socket**：必须关闭且其 goroutine 必须退出，否则泄漏 socket 或在轮次结束后异步写已交出的 socket。
- **被取消的族不得计入 `seedFailures`**：每次都算失败会把「v6 健康」的部署误诊成「seed 一直失败」。
- **两族都失败**：必须走一次 backoff，不能变成不 sleep 的快速重试循环。

---

### Task 1: 抽出「每族选端点」的纯函数（行为不变）

**Files:**
- Modify: `internal/host/direct.go:1409-1424`（`punch()` 里的 family 循环头部）
- Test: `internal/host/direct_v6_test.go`（追加）

**Interfaces:**
- Produces: `func dialFor(f *family, peerV4, peerV6 []netip.AddrPort) netip.AddrPort` — v6 族返回 `peerV6[0]`；v4 族返回 `peerV4[len-1]`，但当 `len(peerV4) > 1` 且 `f.mine[len(f.mine)-1].addr.Addr() == dial.Addr()` 时返回 `peerV4[0]`（hairpin 规则原样保留）。
- Note: `family` 是 `punch()` 内的局部类型（`name string; v6 bool; sock *net.UDPConn; mine []candidate`）。把它提升为包级类型 `family`，字段不变。

- [ ] **Step 1: 写失败测试**

```go
// internal/host/direct_v6_test.go 追加
func TestDialForFamilyAndHairpin(t *testing.T) {
	v6 := []netip.AddrPort{netip.MustParseAddrPort("[2001:db8::5]:3478")}
	peer := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:1111"),
		netip.MustParseAddrPort("203.0.113.9:2222"),
	}
	// 族内顺序：v6 取 first。
	if got := dialFor(&family{v6: true}, peer, v6); got != v6[0] {
		t.Fatalf("v6 dial = %v, want %v", got, v6[0])
	}
	// 不同公网地址：拨对端的 public（last）。
	f := &family{mine: []candidate{{addr: netip.MustParseAddrPort("198.51.100.1:1")},
		{addr: netip.MustParseAddrPort("198.51.100.2:2")}}}
	if got := dialFor(f, peer, v6); got != peer[1] {
		t.Fatalf("v4 dial = %v, want %v", got, peer[1])
	}
	// 同一公网地址（hairpin）：改拨对端的 local（first）。
	f.mine[len(f.mine)-1].addr = netip.MustParseAddrPort("203.0.113.9:9999")
	if got := dialFor(f, peer, v6); got != peer[0] {
		t.Fatalf("hairpin dial = %v, want %v", got, peer[0])
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/host/ -run TestDialForFamilyAndHairpin`
Expected: 编译失败 `undefined: dialFor`

- [ ] **Step 3: 实现**

把 `punch()` 里的局部 `type family struct{...}` 提到包级；把 1409-1424 的 `var dial netip.AddrPort; if f.v6 {...} else {...}` 换成 `dial := dialFor(f, peerV4, peerV6)`。

- [ ] **Step 4: 跑测试与整包**

Run: `go test ./internal/host/ -run 'TestDialForFamilyAndHairpin|TestDirectV6'` 然后 `go test ./internal/host/`
Expected: 全绿（本步不应改变任何行为；整包需要 ~4 分钟）

- [ ] **Step 5: Commit**

```bash
git add internal/host/direct.go internal/host/direct_v6_test.go
git commit -m "refactor(host): name the punch's per-family dial choice"
```

---

### Task 2: 并发换族 + v6 严格优先

**Files:**
- Modify: `internal/host/direct.go:1606-1470`（`punch()` 的「Try each family once」段）
- Test: `internal/host/direct_family_test.go`（新建）

**Interfaces:**
- Produces:
  - `type familyAttempt struct { idx int; dial netip.AddrPort; out seedOutcome; err error }`
  - `func (dc *directConn) startSeed(f *family, dial netip.AddrPort, timeout time.Duration) <-chan familyAttempt` — 起一个 goroutine 跑 `seedHandshakeUDPToken(f.sock, dial, timeout)`，把结果送进**容量 1**的 channel 后关闭它；调用方永不阻塞发送方。
- Consumes: Task 1 的 `dialFor`、`family`；`dc.noteSeedFailure(family string, err error, probeFrom netip.AddrPort)`、`dc.noteErr`、`dc.noteRound`、`dc.markUp(sock, peerAddr, token)`、`pair.noteSeed(result, family, addr string)`。

**裁决规则（严格优先）：**

```
chans := 每族 startSeed（全部同时起飞）
for _, idx := range order:                 // order 已是 v6 在前
    res := <-chans[idx]
    if res.err == nil { winner = idx; break }
    dc.noteSeedFailure(f.name, res.err, res.out.ProbeFrom)
    pair.noteSeed("timeout", f.name, res.dial.String())
if winner < 0 { closeFams(); dc.backoff(); return }
for _, idx := range order {                // 取消其余族
    if idx == winner { continue }
    fams[idx].sock.Close()                 // 已关闭的 socket 再关是 no-op
    if res := <-chans[idx]; res.err == nil {
        pair.noteSeed("ok", fams[idx].name, res.dial.String())  // 已完成且成功：如实记
    }
    // 失败/被取消：不记 noteSeed、不记 noteSeedFailure
    dc.noteRound("%s cancelled (v6 up)", fams[idx].name)
}
win := fams[winner]; sock := win.sock; win.sock = nil
closeFams(); pair.noteSeed("ok", win.name, dials[winner].String())
... // 原有成功路径：notePeerEndpoint(win.out.Answer, announcedFor(...))、dc.mine = win.mine、markUp、log、return
```

- [ ] **Step 1: 写失败测试**（新建文件，复用 `direct_probeoutcome_test.go` 的坏族工具）

```go
// internal/host/direct_family_test.go
package host

// 坏族工具：只回探测包、永不回显我们的 token。
func blindUDP(t *testing.T) (*net.UDPConn, string) {
	t.Helper()
	c := mustListenUDP(t)
	go func() {
		buf := make([]byte, 64)
		var tok [seedTokenLen]byte
		tok[0] = 0xC3
		probe := append(append([]byte(nil), seedProbeMagic[:]...), tok[:]...)
		for {
			n, src, err := c.ReadFromUDP(buf)
			if err != nil { return }
			if n < len(seedProbeMagic) { continue }
			_, _ = c.WriteToUDP(probe, src)
		}
	}()
	return c, c.LocalAddr().String()
}

// v6 是黑洞、v4 通：一轮内必须落到 v4。
func TestPunchFallsBackToV4WhenV6Blind(t *testing.T) {
	/* 两个 engine + fake STUN + relay，engineB.v6Announce 返回 2001:db8::1，
	   engineA/B 的 v6Addr = ::1（保持与 TestDirectV6FallbackToV4 相同搭建）。
	   断言：
	   - 直接路径在 5s 内 up；
	   - engineA.directConn(pubB).peerAddr 是 v4；
	   - dc.attempts 正好增加 1（同一轮收敛）。 */
}

// 两族都通：v6 必须赢，且被丢弃的 v4 attempt 不计失败。
func TestPunchPrefersV6WhenBothWork(t *testing.T) {
	/* 两族都可用（v6 = ::1 两端可达）⇒ 断言：
	   - peerAddr 是 v6；
	   - pair.seedFailures 没有增加（v4 的 attempt 是被取消，不是失败）。 */
}

// 两族都坏：整轮失败并 backoff。
func TestPunchBothFamiliesFailBacksOff(t *testing.T) {
	/* 两族都指到 blindUDP ⇒ 断言 dc.failed 为真且 dc.delay > 0（backoff）。 */
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/host/ -run 'TestPunchFallsBackToV4WhenV6Blind|TestPunchPrefersV6WhenBothWork|TestPunchBothFamiliesFailBacksOff'`
Expected: `TestPunchFallsBackToV4WhenV6Blind` 命中现有的 30s 预算仍可能通过；`TestPunchPrefersV6WhenBothWork` 应因「同轮只尝试 v6 就返回」之外的断言失败（`seedFailures` 或 attempts）；记录实际失败信息后再实现。

- [ ] **Step 3: 实现并发裁决**（上面的伪代码）

注意三点：
1. **socket 只在赢家确定后动**：先 `Close()` 输家的 socket 触发取消，**再** `<-chans[idx]` 等它的 goroutine 退出，最后才 `closeFams()`/交出击家 socket。
2. `dc.noteSeedFailure` 只对**完成且失败**的族调用（它写 `lastErr`）；赢家的 `markUp` 会清空 `lastErr`（direct.go:830）。
3. `pair.noteSeed` 对「完成且成功」的输家仍记 `ok`（如实），对取消/失败只记 trace 行。

- [ ] **Step 4: 跑测试**

Run: `go test ./internal/host/ -run 'TestPunch|TestDirectV6' -v`
Expected: 三个新测试 PASS；`TestDirectV6FallbackToV4` PASS。

- [ ] **Step 5: 收紧 v6 回归预算并加轮数断言**

把 `TestDirectV6FallbackToV4` 的 `waitFor(t, 30*time.Second, ...)` 改回 `10*time.Second`，并加一句断言收敛只用了 1 轮：
`if got := engineA.directConn(pubB).attempts.Load(); got != 1 { t.Fatalf("attempts = %d, want 1 (the families must overlap)", got) }`

Run: `go test ./internal/host/ -run TestDirectV6FallbackToV4 -count=3`
Expected: 3/3 PASS

- [ ] **Step 6: 整包 + race**

Run: `go test ./internal/host/` 然后 `CGO_ENABLED=1 go test -race -count=1 ./internal/host/ -run 'TestPunch|TestDirectV6|TestFaultMute'`
Expected: 全绿，无 `WARNING: DATA RACE`

- [ ] **Step 7: Commit**

```bash
git add internal/host/direct.go internal/host/direct_family_test.go internal/host/direct_v6_test.go
git commit -m "feat(host): attempt both punch families concurrently, v6 first"
```

---

### Task 3: IPv6 改为 opt-in（默认关闭）

**Files:**
- Modify: `config.go:21-22`（`Direct` 旁加 `IPv6`）
- Modify: `internal/host/host.go:79-81`（把开关交给引擎）
- Modify: `internal/host/engine.go:52-54`（`v6Enabled`、`v6Probe`）、`:494-501`（`directConfig`）、`:503-521`（`directReason`）
- Modify: `internal/host/direct.go:325-330`（`directEnabled`）、`:1286-1298`（每轮解析 v6）、`:1330`（`sendCaps`）
- Modify: `status.go:204-215`（`DirectConfig` 加 `IPv6Enabled`）
- Modify: `doctor/doctor.go:99-100`
- Test: `internal/host/v6_switch_test.go`（新建）、`doctor/doctor_test.go`（追加）、`internal/host/config_test.go`（追加）

**Interfaces:**
- Produces:
  - `p2p.Config.IPv6 bool`（yaml `ipv6,omitempty`，零值 false）
  - `engine.v6Enabled bool` — 来自 `Config.IPv6`，在 `host.New` 里赋值
  - `engine.v6Probe func() *net.UDPAddr` — 默认 `v6Egress`，测试注入用
  - `func (e *engine) resolveV6() *net.UDPAddr` — 每轮解析 v6 源并更新 `v6Available`
  - `func (e *engine) caps() uint8` — 返回本次要广播的能力位（v6 位只在可用时置）
  - `p2p.DirectConfig.IPv6Enabled bool`
- Consumes: Task 2 的族列表构造（`fams`）；`v6Egress()`（direct.go:1832）。

**门控点（全部必须）：**

| 位置 | 新行为 |
|---|---|
| `host.New`（host.go:79） | `h.engine.v6Enabled = cfg.IPv6` |
| `Host.Connect`（host.go:109-113） | `if h.engine.v6Enabled { h.engine.v6Available = h.engine.v6Probe() != nil }` |
| `punch()`（direct.go:1286-1298） | `if e.v6Enabled { v6 := e.v6Addr; if v6 == nil { v6 = e.v6Probe() }; if v6 != nil { collectV6 ... } ; e.v6Available = v6 != nil }` — 每轮都探，`v6Available` 只当状态 |
| 候选发送 | `sendCaps(dc.peer, e.caps())`，`caps()` 返回 `capsIPv6` 仅当 `v6Enabled && v6Available` |
| `directEnabled()` | `… || (e.v6Enabled && (e.v6Addr != nil || e.v6Available))` |
| `directConfig()` | `IPv6: e.v6Enabled && (e.v6Addr != nil \|\| e.v6Available)`，并填 `IPv6Enabled: e.v6Enabled` |
| `doctor.go:99` | `ipv6=off` / `ipv6=on (no egress)` / `ipv6=on` |

- [ ] **Step 1: 写失败测试**

```go
// internal/host/v6_switch_test.go
// 关闭时：不发 v6 能力位、不收 v6 候选、不探测。
func TestIPv6OffAdvertisesNothing(t *testing.T) {
	e := newTestEngine(t)                    // v6Enabled 默认 false
	e.stunAddr = "127.0.0.1:1"               // 有 v4 候选源
	e.v6Addr = &net.UDPAddr{IP: net.IPv6loopback} // 即便显式给了 v6，关闭时也不该用
	if got := e.caps(); got&capsIPv6 != 0 {
		t.Fatalf("caps = %#x, want no v6 bit", got)
	}
	if !e.directEnabled() { t.Fatal("v4-only host must still punch") }
}

// 开启时每轮探测：注入 probe，改变它的返回值后再跑一轮，v6Available 必须跟着变。
func TestIPv6OnProbesEveryRound(t *testing.T) {
	e := newTestEngine(t)
	e.v6Enabled = true
	var got atomic.Int32
	e.v6Probe = func() *net.UDPAddr {
		if got.Add(1) == 1 { return nil }
		return &net.UDPAddr{IP: net.IPv6loopback}
	}
	/* 跑两轮 punch 的 v6 解析路径（或直接调用新增的 resolveV6()）⇒ 断言：
	   第一轮 v6Available=false，第二轮 true，且 probe 被调用 2 次。 */
}

// 状态：off / on 但没出口 / on 且可用。
func TestDirectConfigIPv6States(t *testing.T) {
	/* 三个子用例：{v6Enabled:false} ⇒ IPv6=false, IPv6Enabled=false；
	   {v6Enabled:true, 无 egress} ⇒ IPv6=false, IPv6Enabled=true；
	   {v6Enabled:true, v6Addr 有值} ⇒ IPv6=true, IPv6Enabled=true。 */
}

// config：零值即关闭。
func TestIPv6ConfigDefaultsOff(t *testing.T) {
	h, err := New(&p2p.Config{Derp: "wss://127.0.0.1:1/derp", Key: strings.Repeat("cc", 32)})
	if err != nil { t.Fatal(err) }
	if h.engine.v6Enabled { t.Fatal("ipv6 must default off") }
}
```

```go
// doctor/doctor_test.go 追加
func TestReportDirectConfigIPv6States(t *testing.T) {
	cases := []struct{ enabled, available bool; want string }{
		{false, false, "ipv6=off"},
		{true, false, "ipv6=on (no egress)"},
		{true, true, "ipv6=on"},
	}
	// 用 p2p.Status{Direct: p2p.DirectConfig{...}} 调 Report，断言包含 want。
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/host/ -run 'TestIPv6|TestDirectConfigIPv6'` 和 `go test ./doctor/ -run TestReportDirectConfigIPv6States`
Expected: 编译失败（`e.caps` / `e.v6Probe` / `IPv6Enabled` 未定义）

- [ ] **Step 3: 实现门控**（按上表）

要点：
- `v6Probe` 在 `newEngine` 里默认成 `v6Egress`（`engine.go`），测试注入后不再走真实路由查询。
- 把 `punch()` 里「解析 v6 源」抽成 `func (e *engine) resolveV6() *net.UDPAddr`，供测试直接驱动。
- `v6Available` 的写入只留在 `resolveV6`（每轮）与 `Connect` 的首次探测。
- 既有 v6 测试（`direct_v6_test.go`、`direct_test.go` 里设 `v6Addr` 的）全部加 `engineX.v6Enabled = true`。

- [ ] **Step 4: 跑测试**

Run: `go test ./internal/host/ -run 'TestIPv6|TestDirectConfigIPv6|TestDirectV6|TestV4Only'` 然后 `go test ./doctor/` 然后 `go test ./internal/host/`
Expected: 全绿

- [ ] **Step 5: Commit**

```bash
git add config.go status.go internal/host/ doctor/
git commit -m "feat(p2p)!: make the IPv6 direct path opt-in, off by default"
```

（`!` 因为这是配置可见的行为变化：有 v6 出口的旧部署升级后必须显式 `ipv6: true`。）

---

### Task 4: 文档与 e2e 跟进

**Files:**
- Modify: `docs/2026-09-20-p2p-ipv6-direct.md`（决策 3 与「v6 自动启用」的表述）
- Modify: `tests/e2e/**`（若存在 v6 场景的 config 模板）

- [ ] **Step 1: 找出 e2e 里依赖自动 v6 的地方**

Run: `grep -rn "ipv6\|IPv6" tests/e2e/ | head -20`
Expected: 列出场景/config 模板；若某个 config 依赖自动探测，加 `ipv6: true`。

- [ ] **Step 2: 更新旧文档**

在 `docs/2026-09-20-p2p-ipv6-direct.md` 的「已定的决策」第 3 条加一行：
`> 2026-10-23 起改为**并发**换族，见 docs/2026-10-23-p2p-ipv6-preference-design.md；`
并在「候选收集」段把「有全局 v6 就自动启用」改成「需 `ipv6: true`（默认关闭）」。

- [ ] **Step 3: 跑受影响的测试**

Run: `go test ./internal/host/ ./doctor/` 和 `go test ./tests/...`
Expected: 全绿

- [ ] **Step 4: Commit**

```bash
git add docs/2026-09-20-p2p-ipv6-direct.md tests/
git commit -m "docs(p2p): point the ipv6 design at the concurrent, opt-in successor"
```

---

## 验收（全部任务完成后）

- [ ] `gofmt -l .` 无输出；`go vet ./...` 通过。
- [ ] `go test ./internal/host/` 连续 3 次全绿（基线：flaky 修完后已 4/4 绿）。
- [ ] `CGO_ENABLED=1 go test -race -count=1 ./internal/host/` 全绿且无 `WARNING: DATA RACE`。
- [ ] `go test ./ ./cmd/... ./doctor/ ./endpoint/ ./grpc/ ./internal/clock/ ./internal/derpclient/ ./internal/stun/ ./tests/...` 全绿。
- [ ] 手工：在无 v6 的机器上不配 `ipv6` ⇒ `GET /api/p2p/doctor` 显示 `ipv6=off`、peers 段不再出现 v6 候选；配 `ipv6: true` 且无出口 ⇒ `ipv6=on (no egress)`。
- [ ] 提交后推 CI，`build-p2p` 的 build + test（含 `-race`）通过。

## 自检（写完后已跑）

- **Spec 覆盖**：并发换族 → Task 1+2；严格 v6 优先 → Task 2；取消不算失败 → Task 2 步骤 3；预算不动 → 计划里没有任何 `punchTimeout` 改动（符合 spec 的否决）；opt-in 开关与全部 7 个门控点 → Task 3；每轮重探 + `v6Probe` 测试缝 → Task 3；状态/doctor → Task 3；文档 → Task 4。
- **类型一致性**：`family`（Task 1 提升）、`familyAttempt`/`startSeed`（Task 2）、`v6Enabled`/`v6Probe`/`resolveV6`/`caps()`/`IPv6Enabled`（Task 3）在任务间名称一致。
- **Review Focus 的每一条**都落到测试：启动后出现的 v6（`TestIPv6OnProbesEveryRound`）、对端通告而关闭（`TestIPv6OffAdvertisesNothing`）、socket 关闭与并发（Task 2 步骤 6 的 `-race` + `TestPunchPrefersV6WhenBothWork`）、取消不计失败（`TestPunchPrefersV6WhenBothWork` 的 `seedFailures` 断言）、两族都失败（`TestPunchBothFamiliesFailBacksOff`）。
