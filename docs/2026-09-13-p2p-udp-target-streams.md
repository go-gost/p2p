# p2p:udp target 出口化(去 hub/白名单;target 侧流级;gost 侧保留 channel)实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 去掉 hub 模式与 peer 白名单;把 **target 侧**(持 `--target udp://`、无本地 udp dial 的一侧)的通道从"per-peer 预建"改为**流级**(每条入站流现取 target、现拨、流结束即关,零 per-peer 状态)。**gost 侧**(自身 `OpenTunnel(udp)` 的一侧)**保留现有 per-peer `channel`**——它是"本地 udp tunnel 流 ⇄ peer 边"的**通用** rendezvous,不是 hub 专用。准入不在 p2p。

**Architecture:**

- **通道 = 两个"端"的 rendezvous**。端有两种,都通用:(1) **本地 GOST 的 udp `Tunnel` 流**(这台 gost 拨了 udp tunnel);(2) **本机拨的 udp target**(`--target udp://…`)。谁持哪种端是部署形态(tun-to-tun / hub / forward),不影响 p2p 的通用性。
- **端 (1) ⇒ channel 侧(保留)**:`OpenTunnel(udp)`→`openChannel`;`Tunnel` 流经 `stream.go` 的 `attachLocal` 作 channel 的 local 边;peer 边由 opener 的 `ch.loop()` 打开、responder 经 `serveInbound` 的 channel 分支附加。
- **端 (2) ⇒ target 侧(流级,新)**:无 channel;收到带 `P2PU` 的入站流 → 从 udp 池取一个 target → `DialUDP` → 用 `dgramEdge` 把该流 ⇄ 裸 IP 数据报互转,流结束即关连接。**target 侧零 per-peer 状态**。
- **开流仍按公钥序**(`本端 pub < 对端 pub` 者开)。channel 侧的 opener 用 `ch.loop()`;target 侧无 channel,故靠**带内 dial 通知**(新控制帧 `ctrlDialUDP`,由 dial 侧在 `OpenTunnel(udp)` 时发)触发一个带退避的 per-peer opener loop。**护栏**:持 channel 的一侧不再起 dialer(以 channel 为准),否则两者会并发开流、`setStream` last-wins 互关 ⇒ livelock。
- **打洞由拨号触发**,因为拨了号的一方才知道要发 candidates。
- **准入不在 p2p**:谁可用该出口由调用方决定(tun auther / relay `-verify-clients` / 防火墙)。文档必须写明:未认证的 udp target ≈ 直接暴露一个数据面未认证的 tun server。

**Tech Stack:** Go;`github.com/go-gost/p2p`(package main);`net`;`crypto/nacl/box`(经 `derpclient` 的 `SealTo`/`OpenFrom`);测试用 `testing` + `net.Pipe` + 本包内 `relayServer`/`startHubStub` 桩。

**决策记录:**

- 保留公钥序开流、不改成"拨号方开":点对点(两端都拨)在"拨号方开"下会**双开**,而 `setStream` 是 last-wins 并关前驱 → 两条流互相关掉 → livelock。
- **通用性(p2p 不为单一用途特化)**:datagram 通道是"两个端"的 rendezvous;端 (1) 本地 udp `Tunnel` 流、端 (2) udp target 都是通用形态(任何 inner udp dialer / udp 出口都用得到)。故 **`channel` 必须保留**(它是端 (1) 的 rendezvous),只有端 (2) 流级化。**曾考虑**"per-peer 常驻 target 边"(让出口侧源端口跨 flap 稳定,从而省掉 keepalive)——**否决**:那只是为 tun server 那张按源端口做 key 的路由表特化,把应用需求下沉进了传输层。
- **keepalive 归属**:keepalive 在 GOST 的 tun handler(在 p2p 之上),**不是 p2p 的机制**。端口随重连而变是传输层的正常语义(类比 UDP 四元组);重新注册是应用的职责。因此"keepalive 是路由正确性的一部分"指的是 **tun server(出口侧)** 的路由正确性,由 tun app 兑现,**p2p 不依赖它**。
- `ctrlDialUDP` 存在的理由:target 侧**没有 channel**,"target 侧恰好是公钥序 opener"这一半序**没有** `ch.loop()` 可开流,只能靠 dial 侧的带内通知触发 `datagramDialerLoop`。**非冗余**;对端是否响应仍由公钥序唯一决定。
- 本计划**取代** `docs/2026-09-12-p2p-hub-mode.md` 的"白名单 + 预建通道 + hub 模式";那份的 x 侧 keepalive 修复与 `--target` 池仍有效。

**已知约束(必须写进文档):**

- **target 侧**流级 ⇒ 出口侧源端口随**每次 peer 边(重)建立**而变 ⇒ **tun server(出口侧)** 的路由(按 spoke IP)要靠**下一次 keepalive** 刷新。**归属**:这是 tun app 的 keepalive 义务,不是 p2p 的正确性前提;不发 keepalive 的 tun 客户端在第一次重连后下行会永久指向死端口。gost 侧(走 channel)无此问题——它的 local 边是 gost 流,不是 target socket。
- 每条入站流一条到 target 的 UDP socket ⇒ 出口侧 peer 边快速 flap 时有 socket churn(有界、串行,受 opener loop 退避与上限约束)。
- 任何能到达该出口的 peer 都能让出口侧建边 ⇒ 需要 **opener 数上限**兜底(Task 1 里实现,默认 256)。
- **`ctrlDialUDP` 是 best-effort**:控制帧走 DERP WS(`SendPacket`),无 ack。若那一条通知丢失且无新的 `OpenTunnel(udp)`,target 侧的 opener 永不启动 ⇒ 通道建不起来。缓解:每次 dial 都发一遍(最终一致);若要更强,加周期性重发或 ack。

---

## 文件结构

| 文件 | 职责 |
|---|---|
| `p2p/udp.go` | **保留** channel(`openChannel`/`attachLocal`/`serveStream`);抽 `openTaggedStream` 供 `channel.loop` 与 dialer loop 复用;新增 target 侧流级 `serveTargetStream` 与 opener loop `startDatagramDialer`/`stopDatagramDialer`/`stopDatagramDialerOwned`/`datagramDialerLoop`;**删除** `addHubChannel` |
| `p2p/direct.go` | `serveInbound` tagged 分支改为 **channel-first, else target**(**删除** `hubDenied` 守卫,**保留** `e.channel(peer)` 路径);常量加 `ctrlDialUDP`;`sendDialUDP` |
| `p2p/stream.go` | **不改**:gost 侧的 udp `Tunnel` 流仍经 `attachLocal` 作 channel 的 local 边 |
| `p2p/engine.go` | `Engine` 加 `dialers` 字段;`handleControl` 的 `ctrlDialUDP` 分支;`peerGone`/`Close` 清理 dialers;**删除** `hubAllow`/`EnableHub`/`hubDenied`/`hubEnabled` |
| `p2p/server.go` | `OpenTunnel(udp)`:触发打洞 + 发 dial 通知;**删除** hub udp 拒绝 |
| `p2p/main.go` `p2p/config.go` | **删除** `--allow` 与 config `allow` |
| `p2p/*_test.go` | `hub_test.go` 改为 dial-notice 语义(白名单/预建用例删掉);`server_test.go` 删 `TestOpenTunnelHubRefusesUDP`;`config_test.go` 去 `allow`;`direct_test.go` 加打洞触发用例;**新增 tun-to-tun 回归(两侧无 target,两个 key 序)** |
| `p2p/README.md` `README.zh-CN.md` `CLAUDE.md` `docs/` | 去白名单;写明出口全局 / 准入在调用方 / 注入面 / keepalive 归属(tun app) |

---

### Task 1: target 侧流级出口适配(保留 channel)+ 带内 dial 通知 + opener loop

**Files:**
- Modify: `p2p/udp.go`、`p2p/direct.go`、`p2p/engine.go`
- Test: `p2p/dgram_test.go`(新增)、`p2p/hub_test.go`(改写)

- [ ] **Step 1: 写失败测试(流级适配)** — 在 `p2p/dgram_test.go` 末尾追加

```go
// TestServeTargetStreamBridgesFramesToTarget: a tagged inbound stream is served
// purely from the udp pool -- frames on the stream become datagrams at the
// target, and a target datagram comes back as frames on the stream. No channel
// and no per-peer state is involved.
func TestServeTargetStreamBridgesFramesToTarget(t *testing.T) {
	e := newTestEngine(t)
	stub, spec := startHubStub(t)
	if err := e.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	target, _ := e.targets.pick("udp")

	stream, peerSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		e.serveTargetStream(stream, target)
		close(done)
	}()

	// stream -> target: one framed datagram comes out as one datagram; echo a
	// datagram back to the source the stub sees.
	go peerSide.Write(appendFrame(nil, []byte("hello")))
	stub.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, maxFrame)
	n, from, err := stub.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("target got %q, %v; want hello", buf[:n], err)
	}
	if _, err := stub.WriteToUDP([]byte("world"), from); err != nil {
		t.Fatal(err)
	}

	// target -> stream: that datagram comes back framed.
	want := appendFrame(nil, []byte("world"))
	if got := readN(t, peerSide, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("stream got %x, want %x", got, want)
	}

	peerSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveTargetStream did not return after the stream closed")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd p2p && go test -count=1 -run TestServeTargetStreamBridgesFramesToTarget .`
Expected: FAIL —— `e.serveTargetStream undefined`

- [ ] **Step 3: 实现 `serveTargetStream`** — 在 `p2p/udp.go` 末尾追加

```go
// serveTargetStream bridges one inbound datagram stream to a udp target from
// the pool: frame bytes from the stream become datagrams at the target, and
// each datagram comes back as a frame. It is the receive half of a datagram
// channel; nothing outlives the stream, so there is no per-peer state.
// Either direction ending tears the pair down.
func (e *Engine) serveTargetStream(stream net.Conn, target string) {
	defer stream.Close()
	c, err := net.Dial("udp", target)
	if err != nil {
		e.log.Debug("datagram target dial", "target", target, "error", err)
		return
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		e.log.Debug("datagram target is not udp", "target", target)
		return
	}
	edge := newDgramEdge(uc)
	defer edge.Close()

	done := make(chan struct{}, 2)
	go func() { // stream frames -> target datagrams
		buf := make([]byte, channelChunkSize)
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if _, werr := edge.Write(buf[:n]); werr != nil {
					e.log.Debug("datagram target write", "target", target, "error", werr)
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	go func() { // target datagrams -> stream frames
		buf := make([]byte, channelChunkSize)
		for {
			n, err := edge.Read(buf)
			if n > 0 {
				if _, werr := stream.Write(buf[:n]); werr != nil {
					e.log.Debug("datagram stream write", "target", target, "error", werr)
				}
			}
			if err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd p2p && go test -count=1 -run TestServeTargetStreamBridgesFramesToTarget .`
Expected: PASS

- [ ] **Step 5: 写失败测试(dial 通知 + opener 两种序)** — 把依赖白名单/预建通道的用例删掉(`p2p/hub_test.go` 的 `TestEnableHubValidation`、`TestHubDeniedAndChannels`、`TestServeInboundHubGuard`、`TestHubChannelRoundTrip`;`p2p/server_test.go` 的 `TestOpenTunnelHubRefusesUDP`),保留 `startHubStub`、`startTCPCounter`、`waitAccepted` 桩,并新增

```go
// TestDatagramDialNoticeOpensWhenOpener: the dial notice makes a udp-target
// holder open a datagram stream to the notifier, but only when it owns the
// smaller key (the key-order opener). No allowlist is consulted.
func TestDatagramDialNoticeOpensWhenOpener(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for { // hub owns the smaller key, so the hub is the opener
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubH[:], pubS[:]) < 0 {
			break
		}
	}

	hub := newEngine(url, "", privH, slog.Default())
	spoke := newEngine(url, "", privS, slog.Default())
	defer hub.Close()
	defer spoke.Close()
	if err := hub.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := spoke.Connect(); err != nil {
		t.Fatal(err)
	}
	stub, spec := startHubStub(t)
	if err := hub.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}

	chS := spoke.openChannel(pubH)
	defer chS.release()
	spokeLocal := attachLocal(t, chS) // the GOST-side edge (test's end of the pipe)

	if err := spoke.sendDialUDP(pubH); err != nil {
		t.Fatal(err)
	}
	waitStream(t, chS) // the hub opened the peer edge

	go spokeLocal.Write(appendFrame(nil, []byte("hello")))
	got, err := recvDatagram(t, stub)
	if err != nil || string(got) != "hello" {
		t.Fatalf("target got %q, %v; want hello", got, err)
	}
}

// TestDatagramDialNoticeIgnoredWhenResponder: with the target holder owning the
// larger key it is the responder, so the notice must not make it open; the
// notifier (the opener) opens and the holder serves it per stream.
func TestDatagramDialNoticeIgnoredWhenResponder(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for { // spoke owns the smaller key, so the spoke is the opener
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubS[:], pubH[:]) < 0 {
			break
		}
	}

	hub := newEngine(url, "", privH, slog.Default())
	spoke := newEngine(url, "", privS, slog.Default())
	defer hub.Close()
	defer spoke.Close()
	if err := hub.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := spoke.Connect(); err != nil {
		t.Fatal(err)
	}
	stub, spec := startHubStub(t)
	if err := hub.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}

	chS := spoke.openChannel(pubH) // the spoke is the opener: its loop opens
	defer chS.release()
	local := attachLocal(t, chS)
	if err := spoke.sendDialUDP(pubH); err != nil {
		t.Fatal(err)
	}
	waitStream(t, chS)

	go local.Write(appendFrame(nil, []byte("hello")))
	if got, err := recvDatagram(t, stub); err != nil || string(got) != "hello" {
		t.Fatalf("target got %q, %v; want hello", got, err)
	}
}
```

- [ ] **Step 6: 跑测试确认失败**

Run: `cd p2p && go test -count=1 -run 'TestDatagramDialNotice' .`
Expected: FAIL —— `spoke.sendDialUDP undefined`

- [ ] **Step 7: 加控制帧常量与发送助手** — `p2p/direct.go`

```go
const (
	frameControl = 0x00 // [0x00][kind 1B][payload]
	frameData    = 0x01 // [0x01][smux byte stream]

	ctrlPunchCandidates = 0x02 // sealed candidate list
	ctrlDialUDP         = 0x03 // sealed udp-tunnel dial notice
)
```

在 `sendCandidates` 旁追加:

```go
// sendDialUDP tells peer that this host has dialled a udp tunnel toward it, so
// a peer holding a udp target knows a datagram channel is wanted. Sealed so a
// malicious relay cannot forge the notice on a peer's behalf.
func (e *Engine) sendDialUDP(peer derpclient.PublicKey) error {
	return e.sendControl(peer, ctrlDialUDP, e.priv.SealTo(peer, nil))
}
```

- [ ] **Step 8: 处理通知** — `p2p/engine.go` 的 `handleControl` 的 switch 追加

```go
	case ctrlDialUDP:
		if _, ok := e.priv.OpenFrom(src, body[1:]); !ok {
			e.log.Debug("udp dial notice: bad box", "peer", keyName(src))
			return
		}
		// Only the pure target side runs an opener loop: it has no channel, so
		// without this notice (and only in the half of the key orders where it
		// owns the smaller key) nothing would ever open. The channel side has
		// its own ch.loop; starting a second opener here would fight it over
		// setStream (last-wins) and livelock.
		if e.targets.has("udp") && e.channel(src) == nil && bytes.Compare(e.pub[:], src[:]) < 0 {
			e.startDatagramDialer(src)
		}
```

- [ ] **Step 9: 出口侧 opener loop** — `p2p/udp.go` 追加;`Engine` 加字段 `dialers map[derpclient.PublicKey]chan struct{}`(在 `newEngine` 里初始化)

```go
// maxDatagramDialers bounds the per-peer opener loops, so an unbounded stream of
// announcing peers cannot exhaust fds/goroutines.
const maxDatagramDialers = 256

// startDatagramDialer keeps a datagram peer edge to peer alive: open a tagged
// stream, bridge it to a udp target for the stream's lifetime, back off, repeat.
// It runs only on the pure target side, only when it owns the smaller key and a
// udp target exists, and only after the peer announces a udp dial. Idempotent
// per peer.
func (e *Engine) startDatagramDialer(peer derpclient.PublicKey) {
	// The channel side already owns the peer edge (ch.loop); a second opener
	// would fight it over setStream. This dialer is for the pure target side.
	if e.channel(peer) != nil {
		return
	}
	e.mu.Lock()
	if _, ok := e.dialers[peer]; ok {
		e.mu.Unlock()
		return
	}
	if len(e.dialers) >= maxDatagramDialers {
		e.mu.Unlock()
		e.log.Warn("datagram dialer limit reached", "peer", keyName(peer))
		return
	}
	stop := make(chan struct{})
	e.dialers[peer] = stop
	e.mu.Unlock()
	go e.datagramDialerLoop(peer, stop)
}

// stopDatagramDialer ends peer's opener loop (peer gone / engine shutdown).
func (e *Engine) stopDatagramDialer(peer derpclient.PublicKey) {
	e.mu.Lock()
	stop := e.dialers[peer]
	delete(e.dialers, peer)
	e.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// stopDatagramDialerOwned is the loop's own exit cleanup: it drops + closes the
// entry only if it is still this loop's stop, so an exiting loop can never
// clobber a successor registered by handleControl in the meantime (same
// identity discipline as clearStream/clearLocal).
func (e *Engine) stopDatagramDialerOwned(peer derpclient.PublicKey, stop chan struct{}) {
	e.mu.Lock()
	if e.dialers[peer] != stop {
		e.mu.Unlock()
		return
	}
	delete(e.dialers, peer)
	e.mu.Unlock()
	close(stop)
}

// openTaggedStream opens a stream to peer and writes the datagram-channel tag
// before returning it: the tag must precede any frame byte, or the responder
// would read payload as the tag. Shared by channel.loop and datagramDialerLoop.
func (e *Engine) openTaggedStream(pname string) (net.Conn, error) {
	c, err := e.OpenStream(pname)
	if err != nil {
		return nil, err
	}
	if _, werr := c.Write([]byte(channelTag)); werr != nil {
		c.Close()
		return nil, werr
	}
	return c, nil
}

func (e *Engine) datagramDialerLoop(peer derpclient.PublicKey, stop chan struct{}) {
	pname := keyName(peer)
	// Every exit path must drop this peer's dialer entry: a stale entry would
	// consume one of the 256 slots AND make startDatagramDialer early-return
	// forever, so the target side could never re-arm after the channel goes
	// away. The owned variant only touches our own entry.
	defer e.stopDatagramDialerOwned(peer, stop)
	delay := channelRetryMin
	for {
		// A channel may have appeared since the notice (this host dialled too, or
		// an earlier race): it owns the peer edge now, and a second opener would
		// fight ch.loop over setStream. Hand over deterministically.
		if e.channel(peer) != nil {
			return
		}
		openFailed := false
		c, err := e.openTaggedStream(pname)
		if err != nil {
			openFailed = true
			if c != nil {
				c.Close()
			}
			e.log.Debug("datagram dial: open stream", "peer", pname, "error", err)
		} else if target, ok := e.targets.pick("udp"); ok {
			e.log.Info("datagram channel up", "peer", pname)
			e.serveTargetStream(c, target)
			e.log.Info("datagram channel down", "peer", pname)
		} else {
			// Unreachable today (startDatagramDialer runs only when a udp target
			// exists and the pool is fixed after startup); return rather than
			// spin every channelRetryMin if that ever changes.
			e.log.Debug("datagram dial: no udp target", "peer", pname)
			c.Close()
			return
		}
		select {
		case <-e.stop:
			return
		case <-stop:
			return
		case <-time.After(delay):
		}
		delay = channelRetryDelay(delay, openFailed)
	}
}
```

`Engine.Close` 里(与 chans 清理并列)加:遍历 `e.dialers` 逐个 `close(stop)` 并清空 map;`peerGone(peer)` 里加 `e.stopDatagramDialer(peer)`;另在 `openChannel(peer)` 里加 `e.stopDatagramDialer(peer)`——**channel 一旦建立就确定性接管**,连同 loop 每轮复查 `e.channel(peer)!=nil`,消掉"通知早到、channel 后建"的 TOCTOU 双开。外部调用者用**无条件** `stopDatagramDialer`;loop 自身的 `defer` 用 **identity-checked** `stopDatagramDialerOwned`,只动自己的条目(否则退出的 loop 会误删/关掉后来者)。

- [ ] **Step 10: `serveInbound` 的 tagged 分支改为 channel-first, else target** — `p2p/direct.go`,把

```go
	if e.hubDenied(peer) {
		e.log.Warn("hub peer refused", "transport", transport, "peer", keyName(peer))
		stream.Close()
		return
	}

	if tagged, c := peekTag(stream); tagged {
		ch := e.channel(peer)
		if ch == nil {
			// The local gost has not dialled its endpoint yet (a startup race,
			// not an error): drop the stream and let the opener's backoff retry.
			e.log.Debug("channel stream refused", "transport", transport, "peer", keyName(peer))
			c.Close()
			return
		}
		ch.serveStream(c, transport)
		return
	} else if c != stream {
```

替换为

```go
	if tagged, c := peekTag(stream); tagged {
		// Two kinds of datagram end, resolved here:
		//   - the channel side (this host has a local gost udp tunnel for peer):
		//     the peer edge pairs with that gost stream -- the generic path, used
		//     by tun-to-tun and by a spoke dialling a hub;
		//   - the target side (no local gost udp tunnel): serve straight from the
		//     udp target pool for the stream's lifetime, zero per-peer state.
		//     Whether this peer may use the target is the caller's business
		//     (tun auther / firewall), not the transport's.
		if ch := e.channel(peer); ch != nil {
			ch.serveStream(c, transport)
			return
		}
		target, ok := e.targets.pick("udp")
		if !ok {
			e.log.Debug("datagram stream refused (no udp target)", "transport", transport, "peer", keyName(peer))
			c.Close()
			return
		}
		e.log.Info("datagram channel up", "transport", transport, "peer", keyName(peer))
		e.serveTargetStream(c, target)
		e.log.Info("datagram channel down", "transport", transport, "peer", keyName(peer))
		return
	} else if c != stream {
```

- [ ] **Step 11: tun-to-tun 回归(新增)** — `p2p/hub_test.go` 加用例:两侧**都只有** GOST udp dial、**无** `--target`(tun-to-tun 的建模),**两个 key 序各一例**。断言 opener 的 `ch.loop()` 打开的 tagged 流被 responder 的 `serveInbound` 经 **channel 分支**(而非 target 池)接收,gost 流经 channel 双向通透;并断言 responder(无 target)**不会**因"无 udp target"拒流。两个 key 序都要覆盖——只跑一个序会漏掉"channel 存在时不起 dialer"的护栏。

- [ ] **Step 12: 全包回归**

Run: `cd p2p && gofmt -l . && go build ./... && go vet ./... && CGO_ENABLED=1 go test -race -count=1 -timeout 300s .`
Expected: build/vet 干净;测试全绿(此时 `EnableHub`/`hubDenied`/`hubEnabled`/`addHubChannel`/`--allow` 仍在但已无测试依赖,留待 Task 3 删除)

- [ ] **Step 13: Commit**

```bash
cd p2p && git add udp.go direct.go engine.go dgram_test.go hub_test.go && \
git commit -m "p2p: serve datagram streams from the udp pool; in-band udp dial notice"
```

---

### Task 2: 拨号即打洞

**Files:**
- Modify: `p2p/server.go`(OpenTunnel 的 udp 分支)
- Test: `p2p/direct_test.go`

- [ ] **Step 1: 写失败测试** — `p2p/direct_test.go` 追加

```go
// TestUDPDialStartsPunch: dialling a udp tunnel starts hole punching even when
// this side will not open the channel stream -- otherwise, in the half of the
// key orders where the peer is the opener, neither side ever sends candidates
// and the direct path never gets a chance.
func TestUDPDialStartsPunch(t *testing.T) {
	e := newTestEngine(t)
	e.stunAddr = "127.0.0.1:3478" // non-empty only: the punch itself fails fast
	_, peer, _ := derpclient.Generate()

	s := newServer(e)
	if _, err := s.OpenTunnel(context.Background(), &proto.OpenTunnelRequest{
		Peer: keyName(peer), Network: "udp",
	}); err != nil {
		t.Fatal(err)
	}

	dc := e.getDirect(peer)
	if dc == nil {
		t.Fatal("udp dial did not start a punch")
	}
	dc.mu.Lock()
	state := dc.state
	dc.mu.Unlock()
	if state == directNone {
		t.Fatal("udp dial left the punch unstarted")
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `cd p2p && go test -count=1 -run TestUDPDialStartsPunch .`
Expected: FAIL —— `udp dial did not start a punch`

- [ ] **Step 3: 实现** — `p2p/server.go` 的 udp 分支,在 `ch: s.engine.openChannel(key),` 之前插入

```go
			// A dial is the intent to connect: start the punch now instead of only
			// once a stream is opened (which never happens for the responder half
			// of the key orders), and tell the peer a datagram channel is wanted.
			s.engine.maybeStartDirect(key)
			if err := s.engine.sendDialUDP(key); err != nil {
				slog.Debug("udp dial notice", "peer", peer, "error", err)
			}
```

- [ ] **Step 4: 跑测试确认通过**

Run: `cd p2p && go test -count=1 -run TestUDPDialStartsPunch .`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd p2p && git add server.go direct_test.go && \
git commit -m "p2p: a udp dial starts the punch and notifies the peer"
```

---

### Task 3: 删除 hub 模式与白名单机器

**Files:**
- Modify: `p2p/engine.go`、`p2p/udp.go`、`p2p/server.go`、`p2p/config.go`、`p2p/main.go`、`p2p/config_test.go`

- [ ] **Step 1: 删测试侧的 `allow` 痕迹** — `p2p/config_test.go` 的 `TestLoadConfig`:删掉 YAML 里的

```yaml
allow:
  - AAAA
  - BBBB
```

以及断言

```go
	if len(c.Allow) != 2 || c.Allow[0] != "AAAA" || c.Allow[1] != "BBBB" {
		t.Fatalf("allow = %+v", c.Allow)
	}
```

- [ ] **Step 2: 删生产代码** — 精确删除

- `p2p/engine.go`:字段 `hubAllow`;方法 `EnableHub`、`hubDenied`、`hubEnabled`
- `p2p/udp.go`:方法 `addHubChannel`
- `p2p/server.go`:`OpenTunnel` 里的

```go
	if network == "udp" && s.engine.hubEnabled() {
		return nil, status.Errorf(codes.PermissionDenied, "udp tunnel is reserved by hub mode")
	}
```

- `p2p/config.go`:字段 `Allow []string`(含 yaml tag)
- `p2p/main.go`:`--allow` 的 `flag.Func` 块、`allowKeys`/`hubKeys` 解析块、`hub mode requires --derp` 守卫、`if len(hubKeys) > 0 { ... EnableHub ... }` 块

- [ ] **Step 3: 全包回归**

Run: `cd p2p && gofmt -l . && go build ./... && go vet ./... && GOWORK=off go build ./... && CGO_ENABLED=1 go test -race -count=1 -timeout 300s .`
Expected: 全部干净、通过

- [ ] **Step 4: Commit**

```bash
cd p2p && git add engine.go udp.go server.go config.go main.go config_test.go && \
git commit -m "p2p: drop hub mode and the peer allowlist"
```

---

### Task 4: 文档

**Files:**
- Modify: `p2p/README.md`、`p2p/README.zh-CN.md`、`p2p/CLAUDE.md`、`p2p/docs/2026-09-12-p2p-hub-mode.md`

- [ ] **Step 1: README(中英)** — 把 `Hub mode` / `Hub 模式` 一节改写为 `UDP target (a global datagram outlet)` / `UDP target(全局数据报出口)`,内容:

  - `udp://` target 是**全局出口**,不与任何 peer 绑定;任何带 `P2PU` 标记的数据报流都从该池取一条连接转发。
  - **p2p 无准入、无 hub 概念**;谁可用该出口由调用方决定:tun auther 的 per-spoke passphrase、relay 的 `-verify-clients=true`、以及端口绑定/防火墙。
  - **注入面警告**:出口背后的 tun server 数据面未认证 ⇒ 等价于直接暴露一个未认证 tun server。
  - **keepalive 前提**:出口侧源端口随 peer 边重建而变,路由靠下一次 keepalive 刷新;不发 keepalive 的 spoke 在重连后下行会失效。
  - 删掉全部 `--allow` 与"白名单 / fail-closed"表述;flag 表删 `--allow` 行;`--target` 行改为 `repeatable; bare "host:port" feeds the tcp pool, "udp://host:port" the udp pool`。

- [ ] **Step 2: CLAUDE.md** — flag 表删 `--allow`;`Hub mode` 段替换为 `UDP target outlet` 段(无 hub、无名单、流级通道、`ctrlDialUDP` 通知、opener 由公钥序决定);信任边界改为"准入在调用方 + 出口注入面";把 `Current implementation` 那行里的 `+ hub mode` 改回 `+ udp target outlet`。

- [ ] **Step 3: 旧计划标注** — 在 `p2p/docs/2026-09-12-p2p-hub-mode.md` 顶部插入

```markdown
> **已被取代(2026-09-13)**:白名单 + 预建通道 + hub 模式已废弃,改为
> `docs/2026-09-13-p2p-udp-target-streams.md` 的"全局 udp 出口 + 流级通道 + 带内 dial 通知"。
> 本文的 x 侧 keepalive 修复与 `--target` 池仍然有效。
```

- [ ] **Step 4: Commit**

```bash
cd p2p && git add README.md README.zh-CN.md CLAUDE.md docs/ && \
git commit -m "p2p: docs: the udp target is a global outlet; p2p holds no admission"
```

---

### Task 5: e2e 断言更新

**Files:**
- Modify: `/tmp/e2e-hub/run.sh`(scratch,不入库)

- [ ] **Step 1: 换掉"第三个 host 被拒"的断言** — `hub peer refused` 已不存在。改为断言 S3 **能建通道但不通**(它不在 auther 里,拿不到路由):

```bash
ping_ok S3 10.10.0.1 && echo "S3-UNEXPECTEDLY-REACHABLE" || echo "S3-NO-ROUTE-OK"
echo "auth-failed=$(grep -ac 'auth FAILED' "$L/hub-gost.log" || true)"
```

- [ ] **Step 2: 跑 e2e**

Run: `TTL=4s RT=12 /tmp/e2e-hub/run.sh > /tmp/e2e-hub/last-run.log 2>&1; grep -aE '(_OK|_FAIL|-OK|-FAIL)' /tmp/e2e-hub/last-run.log`
Expected: 除 `S3-NO-ROUTE-OK` 外全为 OK;0 个 FAIL

- [ ] **Step 3: 记录** — 把最终断言清单贴回本计划的执行记录(不入库)

---

## 门禁

```bash
cd p2p && gofmt -l . && go build ./... && go vet ./... && GOWORK=off go build ./...
cd p2p && CGO_ENABLED=1 go test -race -count=1 -timeout 300s .
cd x   && go build ./... && go vet ./...          # 未改动,回归确认
E2E 断言全部 PASS(Task 5)
```

## 自检

- **覆盖**:Task 1 = **target 侧**流级适配(`serveTargetStream`)+ **保留 channel** + 带内通知 + target 侧 opener loop;Task 2 = 打洞触发;Task 3 = 去除 hub/白名单;Task 4/5 = 文档与验证。
- **命名一致性**:`serveTargetStream`(Task 1 Step 3)/`sendDialUDP`/`ctrlDialUDP`/`startDatagramDialer`/`stopDatagramDialer`/`datagramDialerLoop`/`e.dialers`/`maxDatagramDialers`(Task 1 Step 7–9)在后续任务引用一致。
- **两个端**:`serveInbound` tagged = **channel-first, else target**(Step 10);护栏 `e.channel(peer)==nil`(Step 8/9)防双开。
- **已定案**:①`maxDatagramDialers` = 256;②`ctrlDialUDP` **保留**(它是 target 侧为 opener 时的唯一触发,非冗余);③keepalive **归属 tun app**(不是 p2p 的正确性前提),文档按此写。
