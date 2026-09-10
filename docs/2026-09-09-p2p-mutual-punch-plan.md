# 互撞拨号打洞 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把打洞从「单边 dial + 单边 accept」改为双方互撞拨号（对称 echo 判据），并开放部署相关的时间参数（`timeouts:` 配置节）。

**Architecture:** 双方各自对对方候选建一个同 conv 的 KCP 会话（`NewConn4(ownConn=true)`），以对称 echo 握手（自己 token 完整往返）判定直连可用；smux 角色仍按 key 序。时间参数经 `-C` YAML 的 `timeouts:` 节注入包级 var，启动时校验。

**Tech Stack:** Go；kcp-go v5.6.72（NewConn4）；smux v1.5.57；goccy/go-yaml。设计依据：`docs/2026-09-09-p2p-mutual-punch-design.md`（v3）。

**约定：** 所有命令在 `p2p/` 目录执行；每个 Task 结束跑 `go build ./... && go vet ./...` 与 `CGO_ENABLED=1 go test -race -count=1 ./...`。Commit 步骤按用户 no-auto-commit 惯例，等用户确认后执行。

---

### Task 1: smux keepalive 参数统一为包级 var

**Files:**
- Modify: `p2p/engine.go`（const `keepAlivePeriod` 区域约 74–87 行；`ensureSessionLocked` 约 488–497）
- Modify: `p2p/direct.go`（`punch()` 内 smux cfg 约 422–429）

- [ ] **Step 1: engine.go 新增包级 var 并替换两处硬编码**

在 `const` 块之后加：

```go
// smux keepalive, shared by the relay and direct sessions. KeepAliveTimeout
// must stay well above the interval (>= 2x): with them equal, smux's idle
// check races the first NOP round-trip and closes an idle session after
// ~interval (see docs/2026-09-09-p2p-mutual-punch-design.md, kcp-go deep
// dive R1/R2). Configurable via `timeouts.smux`.
var (
	smuxKeepAliveInterval = 10 * time.Second
	smuxKeepAliveTimeout  = 30 * time.Second
)
```

`keepAlivePeriod` 从 `const` 移到 var（timeouts 要改它）：

```go
	// keepAlivePeriod pings the DERP server well below typical proxy idle
	// timeouts (e.g. Cloudflare's ~100s).
	keepAlivePeriod = 30 * time.Second
```

（把 `keepAlivePeriod` 行从原 const 块删除、加进上面的 var 块。）

`ensureSessionLocked` 里：

```go
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
```

（注释保留原有的“must exceed / 3x gap”说明，删掉重复的注释行。）

- [ ] **Step 2: direct.go punch() 改用同一对 var**

```go
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
```

- [ ] **Step 3: 验证**

Run: `go build ./... && go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./...`
Expected: 25 passed。

- [ ] **Step 4: Commit（待用户确认）**

```bash
git add engine.go direct.go
git commit -m "p2p: unify smux keepalive into package vars"
```

---

### Task 2: `timeouts:` 配置节

**Files:**
- Modify: `p2p/config.go`
- Modify: `p2p/main.go`（`setupLogger` 调用之后、engine 创建之前）
- Test: `p2p/config_test.go`

- [ ] **Step 1: 写失败测试**

`config_test.go` 追加：

```go
// TestApplyTimeouts covers validation and application of the timeouts section:
// zero values keep defaults, invalid values are rejected, and a valid set is
// applied to the package-level timing vars.
func TestApplyTimeouts(t *testing.T) {
	oldPunchWait, oldBackoff := punchWaitTimeout, backoffPeriod
	oldI, oldT := smuxKeepAliveInterval, smuxKeepAliveTimeout
	t.Cleanup(func() {
		punchWaitTimeout, backoffPeriod = oldPunchWait, oldBackoff
		smuxKeepAliveInterval, smuxKeepAliveTimeout = oldI, oldT
	})

	// nil and zero values: no-op
	if err := applyTimeouts(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	if err := applyTimeouts(&TimeoutsConfig{}); err != nil {
		t.Fatalf("zero: %v", err)
	}

	// negative rejected
	if err := applyTimeouts(&TimeoutsConfig{PunchWait: -time.Second}); err == nil {
		t.Fatal("negative punchWait accepted")
	}

	// smux timeout < 2x interval rejected
	if err := applyTimeouts(&TimeoutsConfig{Smux: &SmuxTimeouts{
		Interval: 10 * time.Second, Timeout: 19 * time.Second,
	}}); err == nil {
		t.Fatal("smux timeout < 2x interval accepted")
	}

	// valid: applied
	if err := applyTimeouts(&TimeoutsConfig{
		PunchWait: 7 * time.Second,
		Backoff:   45 * time.Second,
		Smux: &SmuxTimeouts{Interval: 5 * time.Second, Timeout: 10 * time.Second},
	}); err != nil {
		t.Fatal(err)
	}
	if punchWaitTimeout != 7*time.Second || backoffPeriod != 45*time.Second {
		t.Fatalf("punchWait=%v backoff=%v", punchWaitTimeout, backoffPeriod)
	}
	if smuxKeepAliveInterval != 5*time.Second || smuxKeepAliveTimeout != 10*time.Second {
		t.Fatalf("smux=%v/%v", smuxKeepAliveInterval, smuxKeepAliveTimeout)
	}
}
```

同时给 `TestLoadConfig` 增加解析断言（在既有合法 YAML 后追加）：

```yaml
timeouts:
  punchWait: 7s
  smux:
    interval: 5s
    timeout: 10s
```

```go
	if c.Timeouts == nil || c.Timeouts.PunchWait != 7*time.Second {
		t.Fatalf("timeouts.punchWait = %+v", c.Timeouts)
	}
	if c.Timeouts.Smux == nil || c.Timeouts.Smux.Interval != 5*time.Second {
		t.Fatalf("timeouts.smux = %+v", c.Timeouts.Smux)
	}
```

需要在 config_test.go 的 import 加 `"time"`。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -run 'TestApplyTimeouts|TestLoadConfig' .`
Expected: 编译失败（`undefined: applyTimeouts` / `TimeoutsConfig`）。

- [ ] **Step 3: 实现 config.go**

```go
// TimeoutsConfig tunes deployment-dependent timings. Zero values keep the
// built-in defaults; internal mechanism timeouts stay hardcoded.
type TimeoutsConfig struct {
	PunchWait     time.Duration `yaml:"punchWait,omitempty"`
	Punch         time.Duration `yaml:"punch,omitempty"`
	Seed          time.Duration `yaml:"seed,omitempty"`
	Backoff       time.Duration `yaml:"backoff,omitempty"`
	DerpKeepAlive time.Duration `yaml:"derpKeepAlive,omitempty"`
	Smux          *SmuxTimeouts `yaml:"smux,omitempty"`
}

// SmuxTimeouts tunes the shared relay/direct smux keepalive.
type SmuxTimeouts struct {
	Interval time.Duration `yaml:"interval,omitempty"`
	Timeout  time.Duration `yaml:"timeout,omitempty"`
}
```

`Config` 加字段：`Timeouts *TimeoutsConfig \`yaml:"timeouts,omitempty"\``。

（`Seed` 字段本 Task 只定义与校验；Task 3 引入 `seedTimeout` var 后再在 applyTimeouts 里赋值——见 Task 3 Step 3。）

```go
// applyTimeouts validates and applies the timeouts config to the package-level
// timing vars. Zero values keep defaults; invalid values are rejected at
// startup so a misconfiguration fails loudly instead of producing a silently
// broken punch. smux timeout must be >= 2x the interval: smux's own
// VerifyConfig only requires >=, and the failing case we hit twice was
// equality (an idle session kills itself).
func applyTimeouts(t *TimeoutsConfig) error {
	if t == nil {
		return nil
	}
	for name, v := range map[string]time.Duration{
		"punchWait": t.PunchWait, "punch": t.Punch, "seed": t.Seed,
		"backoff": t.Backoff, "derpKeepAlive": t.DerpKeepAlive,
	} {
		if v < 0 {
			return fmt.Errorf("timeouts.%s must be positive", name)
		}
	}
	if t.Smux != nil {
		if t.Smux.Interval < 0 || t.Smux.Timeout < 0 {
			return errors.New("timeouts.smux values must be positive")
		}
		interval, timeout := smuxKeepAliveInterval, smuxKeepAliveTimeout
		if t.Smux.Interval != 0 {
			interval = t.Smux.Interval
		}
		if t.Smux.Timeout != 0 {
			timeout = t.Smux.Timeout
		}
		if timeout < 2*interval {
			return fmt.Errorf("timeouts.smux.timeout (%s) must be >= 2x interval (%s)", timeout, interval)
		}
	}

	if t.PunchWait != 0 {
		punchWaitTimeout = t.PunchWait
	}
	if t.Punch != 0 {
		punchTimeout = t.Punch
	}
	if t.Backoff != 0 {
		backoffPeriod = t.Backoff
	}
	if t.DerpKeepAlive != 0 {
		keepAlivePeriod = t.DerpKeepAlive
	}
	if t.Smux != nil {
		if t.Smux.Interval != 0 {
			smuxKeepAliveInterval = t.Smux.Interval
		}
		if t.Smux.Timeout != 0 {
			smuxKeepAliveTimeout = t.Smux.Timeout
		}
	}
	return nil
}
```

imports 加 `"errors"`、`"time"`。

- [ ] **Step 4: main.go 接线**

`setupLogger` 成功之后、`var engine *Engine` 之前：

```go
	if err := applyTimeouts(cfg.Timeouts); err != nil {
		slog.Error("timeouts", "error", err)
		os.Exit(1)
	}
```

- [ ] **Step 5: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -count=1 ./...`
Expected: 全绿（27 passed 上下）。

- [ ] **Step 6: Commit（待用户确认）**

```bash
git add config.go config_test.go main.go
git commit -m "p2p: timeouts config section (validated, smux timeout >= 2x interval)"
```

---

### Task 3: `seedHandshake` 对称 echo 握手

**Files:**
- Modify: `p2p/direct.go`（新增 var + 函数；替换 `primeKCP`，Task 5 删除旧用法）
- Test: `p2p/direct_test.go`

- [ ] **Step 1: 写失败测试**

`direct_test.go` 追加：

```go
// scriptConn is a net.Conn fed by a fixed reader; writes are discarded.
type scriptConn struct{ io.Reader }

func (scriptConn) Write(p []byte) (int, error) { return len(p), nil }
func (scriptConn) Close() error                { return nil }
func (scriptConn) LocalAddr() net.Addr         { return nil }
func (scriptConn) RemoteAddr() net.Addr        { return nil }
func (scriptConn) SetDeadline(time.Time) error      { return nil }
func (scriptConn) SetReadDeadline(time.Time) error  { return nil }
func (scriptConn) SetWriteDeadline(time.Time) error { return nil }

// TestSeedHandshake covers the symmetric echo handshake: two peer ends
// complete when both directions flow; a half-open path (peer token arrives,
// own echo never comes) must fail — the "false direct" regression.
func TestSeedHandshake(t *testing.T) {
	// success: both ends over an in-memory pipe, concurrently
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	errs := make(chan error, 2)
	go func() { errs <- seedHandshake(c1, 5*time.Second) }()
	go func() { errs <- seedHandshake(c2, 5*time.Second) }()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("seedHandshake: %v", err)
		}
	}

	// half-open: peer token arrives (1 byte), then EOF — own echo never comes
	if err := seedHandshake(scriptConn{Reader: bytes.NewReader([]byte{42})}, time.Second); err == nil {
		t.Fatal("half-open seed unexpectedly succeeded")
	}
}
```

imports 需 `"bytes"`（net/time/io 已有）。

- [ ] **Step 2: 跑测试确认失败**

Run: `CGO_ENABLED=1 go test -race -run TestSeedHandshake .`
Expected: 编译失败（`undefined: seedHandshake`）。

- [ ] **Step 3: 实现**

`direct.go` 的 var 块加：

```go
	// seedTimeout bounds the symmetric echo handshake (both peers must see
	// their own token round-trip before streams ride the session).
	seedTimeout = 5 * time.Second
```

（同时删除 `candidateTimeout`——它的唯一使用者 `primeKCP` 在 Task 4 被删；此步先保留 primeKCP 编译，Task 4 一起删。）

在 `primeKCP` 旁新增：

```go
// seedHandshake runs the symmetric echo handshake over a fresh KCP session.
// Both peers execute the same four steps — write own token, read the peer's
// token, echo it back, then require the own token's echo. Success therefore
// proves a full own->peer->own round trip on both sides; a half-open path
// (we can receive but our bytes never arrive) fails instead of producing a
// "false direct" session whose streams would blackhole. KCP retransmits the
// unacked bytes, so the window also covers a NAT mapping that only opens
// after the peer's first packet (k3s conntrack-assist).
func seedHandshake(c net.Conn, timeout time.Duration) error {
	c.SetDeadline(time.Now().Add(timeout))
	defer c.SetDeadline(time.Time{}) // clear: the session must outlive the seed

	var token [1]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	if _, err := c.Write(token[:]); err != nil {
		return err
	}
	var peer [1]byte
	if _, err := io.ReadFull(c, peer[:]); err != nil {
		return err
	}
	if _, err := c.Write(peer[:]); err != nil { // echo the peer's token
		return err
	}
	var echo [1]byte
	if _, err := io.ReadFull(c, echo[:]); err != nil {
		return err
	}
	if echo[0] != token[0] {
		return errors.New("derp engine: seed echo mismatch")
	}
	return nil
}
```

imports 加 `"crypto/rand"`。

Task 2 的 `applyTimeouts` 现补一行（放在 `if t.Backoff != 0` 旁）：

```go
	if t.Seed != 0 {
		seedTimeout = t.Seed
	}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `CGO_ENABLED=1 go test -race -run TestSeedHandshake .`
Expected: PASS。

- [ ] **Step 5: Commit（待用户确认）**

```bash
git add direct.go direct_test.go config.go
git commit -m "p2p: symmetric seed handshake for direct sessions"
```

---

### Task 4: punch() 重写为互撞拨号

**Files:**
- Modify: `p2p/direct.go`（`punch()` 299–452；删除 `primeKCP` 457–468、`kcpAccept` 470–501、`dummyProbe` 503–517、`candidateTimeout`）

- [ ] **Step 1: 重写 punch()**

用以下实现**整体替换** `punch()` 函数（含 socket 绑定与 STUN 段；旧实现的角色分支、dummyProbe、prime 路径全部去除）：

```go
func (dc *directConn) punch() {
	e := dc.e
	// The smux session role (smaller key = client) is independent of who
	// dials: both peers dial. See docs/2026-09-09-p2p-mutual-punch-design.md.
	roleIsClient := bytes.Compare(e.pub[:], dc.peer[:]) < 0
	pname := keyName(dc.peer)

	// Bind the punch socket to the egress IP toward the STUN server so the
	// local address we advertise is a concrete, peer-reachable endpoint
	// (same-NAT / same-LAN peers connect over it directly). Falls back to a
	// wildcard bind when the IP cannot be determined.
	socket, err := net.ListenUDP("udp4", bindAddrFor(e.stunAddr))
	if err != nil {
		e.log.Debug("direct punch: udp socket", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	keep := false
	defer func() {
		if !keep {
			socket.Close() // idempotent: the kcp session may own the socket
		}
	}()

	e.log.Debug("direct punch: start", "peer", pname)

	// 1. Learn our own public endpoint from the same socket we'll punch with,
	// so the NAT mapping is identical.
	ctx, cancel := context.WithTimeout(context.Background(), stunTimeout)
	pubEP, err := stun.Lookup(ctx, e.stunAddr, socket)
	cancel()
	if err != nil {
		e.log.Debug("direct punch: stun failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: stun ok", "peer", pname, "public", pubEP.String())

	// 2. Advertise our endpoints to the peer: the local socket address first
	// (directly reachable when the peers share a network — same NAT/LAN
	// hairpin), then the STUN public mapping for cross-NAT.
	localEP := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	mine := []candidate{{addr: localEP}, {addr: pubEP}}
	if len(mine) == 2 && mine[0].addr == mine[1].addr {
		mine = mine[:1] // no NAT: local == public
	}
	if err := e.sendCandidates(dc.peer, mine); err != nil {
		e.log.Debug("direct punch: send candidates failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: candidates sent", "peer", pname, "candidates", candAddrs(mine))

	// 3. Wait for the peer's candidates (exchanged over the relay control
	// channel, so this works even while no UDP path exists yet).
	ctx, cancel = context.WithTimeout(context.Background(), punchTimeout)
	defer cancel()
	cands, ok := dc.waitCandidates(ctx)
	if !ok {
		e.log.Debug("direct punch: no peer candidates", "peer", pname)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: peer candidates", "peer", pname, "candidates", candAddrs(cands))
	peerAddrs := ipv4Addrs(cands)
	if len(peerAddrs) == 0 {
		e.log.Debug("direct punch: no ipv4 candidate", "peer", pname, "candidates", candAddrs(cands))
		dc.backoff()
		return
	}

	// 4. Mutual dial: both peers build their KCP session with the same conv.
	// Only ONE candidate is dialed per side — kcp-go spawns one readLoop per
	// client session, so two sessions on one socket would steal each other's
	// packets. Same NAT (hairpin) dials the peer's local address, otherwise
	// its public one; the rule is symmetric, so both sides agree.
	dial := peerAddrs[len(peerAddrs)-1] // default: public (cross-NAT)
	if len(peerAddrs) > 1 && pubEP.Addr() == dial.Addr() {
		dial = peerAddrs[0] // same NAT: local (hairpin)
	}
	u := net.UDPAddrFromAddrPort(dial)
	e.log.Debug("direct punch: dial", "peer", pname, "addr", u.String(), "conv", dc.conv())
	// ownConn=true: Close closes the socket, so session death tears down the
	// readLoop with no separate bookkeeping (kcp-go deep-dive R2).
	kcpConn, err := kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, socket)
	if err != nil {
		e.log.Debug("direct punch: dial failed", "peer", pname, "addr", u.String(), "error", err)
		dc.backoff()
		return
	}
	if err := seedHandshake(kcpConn, seedTimeout); err != nil {
		kcpConn.Close()
		e.log.Debug("direct punch: seed failed", "peer", pname, "addr", u.String(), "error", err)
		dc.backoff()
		return
	}
	e.log.Debug("direct punch: seed ok", "peer", pname, "peerAddr", dial.String())

	// 5. smux over KCP; role by key order (external to who dialed).
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = smuxKeepAliveInterval
	cfg.KeepAliveTimeout = smuxKeepAliveTimeout
	var sess *smux.Session
	if roleIsClient {
		sess, err = smux.Client(kcpConn, cfg)
	} else {
		sess, err = smux.Server(kcpConn, cfg)
	}
	if err != nil {
		kcpConn.Close()
		e.log.Debug("direct punch: smux failed", "peer", pname, "error", err)
		dc.backoff()
		return
	}

	dc.markUp(sess, socket, dial)
	keep = true

	e.log.Debug("direct established", "peer", pname,
		"local", mine[0].addr.String(), "public", pubEP.String(), "peerAddr", dial.String())
	go func() {
		e.acceptLoop(sess, "direct", pname, dial.String())
		dc.markDead(sess)
	}()
}
```

- [ ] **Step 2: 删除退役代码**

删除：`primeKCP`、`kcpAccept`、`dummyProbe`、`candidateTimeout` var、以及 `punch()` 旧实现的全部残余；`direct.go` 顶部注释里 "Both peers keep an accept loop..." 更新为互撞描述。

检查残留引用：`grep -n 'primeKCP\|kcpAccept\|dummyProbe\|candidateTimeout' direct.go` → 应无输出。
`kcp.ServeConn` 不再使用（kcp 包仍用于 NewConn4）；`netip` 仍被 candidate 等使用。

- [ ] **Step 3: 既有测试全绿**

Run: `go build ./... && go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./...`
Expected: 全绿。既有 direct 测试（round-trip / survives-punch-timeout / fallback-to-relay / local-candidate / stun-unreachable / repunch-after-death / repunch-after-missed-gone）在互撞下语义不变，必须全部通过——它们是本次重写的回归网。

- [ ] **Step 4: Commit（待用户确认）**

```bash
git add direct.go
git commit -m "p2p: mutual simultaneous punch (both peers dial, symmetric seed)"
```

---

### Task 5: 升格 spike 回归测试

**Files:**
- Test: `p2p/direct_test.go`

- [ ] **Step 1: 加入互撞合并回归测试**

（内容来自已删除的 spike 文件，已验证通过；这里固定为回归，防 kcp-go 行为变更。）

```go
// TestMutualNewConn3Merge: two kcp.NewConn3 endpoints dialing each other's
// address with the same conv merge into one working bidirectional session
// without any listener — the transport-level property the mutual punch
// relies on.
func TestMutualNewConn3Merge(t *testing.T) {
	conv := uint32(0x12345678)
	sockA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockA.Close()
	sockB, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sockB.Close()

	a, err := kcp.NewConn3(conv, sockB.LocalAddr(), nil, 0, 0, sockA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := kcp.NewConn3(conv, sockA.LocalAddr(), nil, 0, 0, sockB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { // A writes, then reads B's reply
		defer wg.Done()
		a.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.Write([]byte("hello-from-A")); err != nil {
			errs <- err
			return
		}
		buf := make([]byte, 64)
		n, err := a.Read(buf)
		if err != nil {
			errs <- err
			return
		}
		if string(buf[:n]) != "hello-from-B" {
			errs <- fmt.Errorf("A got %q", buf[:n])
		}
	}()
	go func() { // B reads, then writes
		defer wg.Done()
		b.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, err := b.Read(buf)
		if err != nil {
			errs <- err
			return
		}
		if string(buf[:n]) != "hello-from-A" {
			errs <- fmt.Errorf("B got %q", buf[:n])
			return
		}
		if _, err := b.Write([]byte("hello-from-B")); err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestMutualKCPWithSmux: smux over a mutual KCP pair, roles by key order
// (external to who dialed), streams in both directions.
func TestMutualKCPWithSmux(t *testing.T) {
	conv := uint32(0x9abcdef0)
	sockA, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sockA.Close()
	sockB, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer sockB.Close()

	a, err := kcp.NewConn3(conv, sockB.LocalAddr(), nil, 0, 0, sockA)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := kcp.NewConn3(conv, sockA.LocalAddr(), nil, 0, 0, sockB)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); seedHandshake(a, 3*time.Second) }()
	go func() { defer wg.Done(); seedHandshake(b, 3*time.Second) }()
	wg.Wait()

	cfg := smux.DefaultConfig()
	sessA, err := smux.Client(a, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sessA.Close()
	sessB, err := smux.Server(b, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sessB.Close()

	accepted := make(chan *smux.Stream, 1)
	go func() {
		s, err := sessB.AcceptStream()
		if err != nil {
			t.Errorf("B accept: %v", err)
			return
		}
		accepted <- s
	}()
	s1, err := sessA.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	bs := <-accepted
	defer bs.Close()

	s1.SetDeadline(time.Now().Add(5 * time.Second))
	bs.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s1.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(bs, buf); err != nil {
		t.Fatalf("B read: %v", err)
	}
	if _, err := bs.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(s1, buf); err != nil {
		t.Fatalf("A read: %v", err)
	}
}
```

注意：两个 spike 测试用 `seedHandshake` 作为 seed 步骤（等价原 spike 的手工 seed），确保本测试不依赖 punch 实现。

imports 需 `"fmt"`、`"sync"`、`kcp-go/v5`、`smux`（direct_test.go 现无这些）。

- [ ] **Step 2: 跑全部**

Run: `go build ./... && go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./...`
Expected: 全绿。

- [ ] **Step 3: Commit（待用户确认）**

```bash
git add direct_test.go
git commit -m "p2p: regression tests for mutual KCP merge and smux-over-mutual"
```

---

### Task 6: 文档

**Files:**
- Modify: `p2p/README.md`、`p2p/README.zh-CN.md`（打洞段 + `timeouts:` 配置示例）
- Modify: `p2p/CLAUDE.md`（架构段：打洞改为互撞；`timeouts` 说明）
- Modify: `p2p/docs/2026-09-09-p2p-mutual-punch-design.md`（状态改 shipped 或注明实现差异）

- [ ] **Step 1: README 打洞段落更新（en/zh）**

英文段（Hole punching 节）追加/改写：

```
The punch is **symmetric**: both peers dial each other's candidate with the
same deterministic KCP conv, and a session is only used once both sides
complete the echo handshake (each peer must see its own token round-trip).
This removes the old "one side dials, the other accepts" asymmetry, which
failed when only one direction could be punched (e.g. a peer inside a k3s
pod whose inbound UDP needs the peer to have sent first).
```

zh 对应段同义改写。

- [ ] **Step 2: 加 `timeouts:` 配置示例到 README（en/zh）**

```yaml
timeouts:
  punchWait: 5s       # OpenStream waits this long for a direct path before relay
  punch: 10s          # whole-punch window (candidate wait + dial/seed)
  seed: 5s            # symmetric echo handshake window
  backoff: 30s        # re-punch retry interval after a failed attempt
  derpKeepAlive: 30s  # DERP keepalive (must stay below proxy idle timeouts)
  smux:
    interval: 10s
    timeout: 30s      # must be >= 2x interval
```

一句话说明：仅 config 可设、未设用默认、非法启动即报错。

- [ ] **Step 3: CLAUDE.md 更新**

- 架构段「Direct data plane」：改为互撞描述（双方 NewConn4 + seedHandshake + smux key 序），删 dummyProbe/ServeConn/primeKCP 描述。
- flag 表下方补一句 `timeouts:` 配置节。

- [ ] **Step 4: 设计文档标注实现状态**

`docs/2026-09-09-p2p-mutual-punch-design.md` 头部状态行改为：
`状态：implemented（2026-09-09）`；「测试」节里 NAT shim 一条改为：
「半通路径由 `TestSeedHandshake`（对端 token 到达但自身 echo 不回 → 判败）覆盖；完整 conntrack
时序在 k3s 实测验证」——进程内 shim 需要侵入式测试缝，不做。

- [ ] **Step 5: 验证 + Commit（待用户确认）**

Run: `go build ./... && go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./...`
然后 commit：

```bash
git add README.md README.zh-CN.md CLAUDE.md docs/2026-09-09-p2p-mutual-punch-design.md
git commit -m "p2p: document mutual punch and timeouts config"
```

---

## 验证（端到端，全部 Task 完成后）

```bash
cd p2p
go build ./... && go vet ./...
GOWORK=off go build ./...            # 独立构建
CGO_ENABLED=1 go test -race -count=1 ./...   # 含新增 4 个测试
```

手工 e2e（沿用既有 derper + 两 host 拓扑，见 docs/2026-09-07-p2p-m2-holepunch.md）：
两个 host 各起 `--derp ... --stun ...`，A 静态 forward / B `--target`，curl 直连命中；
A/B 日志出现 `direct established` 且 `transport=direct`；kill relay 数据后直连仍通。

k3s 实测（用户在部署环境跑）：pod host + NAT client，验证「原先只能单向打洞」的场景下
`direct established` 出现在**双方**日志。
