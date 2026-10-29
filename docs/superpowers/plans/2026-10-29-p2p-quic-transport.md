# p2p QUIC transport（relay + direct 单连接多路径）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 opt-in 的 QUIC 数据面：每个 peer 一条 QUIC 连接，relay（DERP + batching）和 direct（打洞 UDP）是它的两条 path；QUIC 模式下 TLS/QUIC 取代 secure/KCP/smux，KCP 与 QUIC 全局互斥、无 fallback。

**Architecture:** `transport=kcp` 保持现有 secure+KCP+smux 路径不变；`transport=quic` 下每 peer 一个 `quic.Transport`（零长度 connection ID）+ 一个 `multiPathConn`。QUIC 连接先在 relay underlay 上建立，direct 打通后加入第二条 underlay；client（小公钥）用 preferred 写路径驱动，server 通过 QUIC path validation 跟随。direct/relay 的切换只发生在同一条 QUIC 连接内；不回 KCP。

**Tech Stack:** Go 1.26.4（`p2p/go.mod`）；`github.com/quic-go/quic-go v0.63.0`；现有 DERP/KCP/smux；TLS 1.3；标准库 `crypto/ed25519`、`crypto/tls`、`crypto/x509`。

**Spec:** `p2p/docs/superpowers/specs/2026-10-29-p2p-quic-transport-design.md`

## Global Constraints

- 只改 `p2p/` 模块；不改 `core/`、不改 `plugin/` 的 proto（gRPC proto 冻结，QUIC 新字段 in-process only）。
- KCP 是默认模式；QUIC 是严格 opt-in。QUIC 模式下不建 KCP pair/session，**无 fallback**。要回 KCP 只能改配置并重启。
- 每个 peer **一个** `quic.Transport`，`ConnectionIDGenerator` 必须是零长度（`ConnectionIDLen()==0`）；不能跨 peer 共享 Transport。spike 证明默认 CID 池第二次迁移会耗尽。
- QUIC 数据面：relay 走 DERP `frameData` + `[uint16 len][packet]...` batching（32 KiB / 200 µs），direct 走打洞 UDP；QUIC packet 默认 1200，`DisablePathMTUDiscovery=true`。
- TLS：自签 Ed25519 证书；SHA-256(DER) 指纹放 `ctrlCaps` 的 `tlvVersion=1` TLV；双向 pin；ALPN `p2p-quic/1`；无 0-RTT。
- caps 旧格式 `[caps 1B]` 必须继续可用；QUIC 新格式 `[caps][tlvVersion=1][TLV...]`。旧 peer 只看 `clear[0]`。
- direct 复用现有 `directConn`/seed/candidate/heartbeat/backoff；不改打洞决策，只改“安装/退役 direct underlay”的落点。
- 注释只写英文（[[english-only-comments]]）。Go 工具链不在非登录 shell 的 PATH ⇒ 命令用 `bash -lc` 包一层。
- 本机通配 `go test ./...` 会挂住 ⇒ 逐包跑；`p2p` 是独立仓库 ⇒ git 命令在 `p2p/` 目录执行。
- **不要自动 commit / push**（[[no-auto-commit]]）：本计划的 Commit 步骤只在用户明确要求时执行；否则保留 working tree 并报告。
- 跨模块/工作区验证用 `GOWORK=off`；race 测试用 `CGO_ENABLED=1`。
- 开工前 `p2p/internal/host/relaykcp.go` 与 `p2p/internal/host/session_lock_test.go` 有**未提交的用户改动**；不要 revert/覆盖。Task 11 碰到 `relaykcp.go` 前先重读工作区版本，改动只做 QUIC 分支的最小插入。

## Review Focus

1. **strict QUIC vs KCP-only peer**：QUIC 模式下对端没有 QUIC bit 必须返回 `ErrTransportUnsupported`，且**不创建 KCP pair/session**；不能退回 KCP。→ Task 13 `TestQUICModeRejectsKCPPeer`
2. **TLS pinning**：错误/缺失 FP、缺 client cert、ALPN 不匹配必须 fail closed，不能建立连接。→ Task 3 `TestQUICTLSRejectsWrongFingerprint`/`TestQUICTLSRequiresClientCert`，Task 13 `TestQUICModeNoPinNoConnection`
3. **zero-CID / one Transport per peer**：两个 peer 的 Transport/连接不能互相路由；一个 Transport 只承载一条连接。→ Task 4 `TestZeroCIDGenerator`，Task 7 `TestQUICPairTwoPeersIsolated`，Task 13 `TestQUICModeMultiPeerIsolation`
4. **direct underlay 替换/关闭**：旧 underlay 的 read error 不能透传给 QUIC transport；re-punch 替换 socket 时连接和流不能被杀。→ Task 4 `TestMultiPathReplaceUnderlayIgnoresOldError`，Task 9 `TestQUICPairMigratesRelayDirectRelay`
5. **迁移中的流完整性**：direct→relay→direct 切换时双向数据无丢/无乱序；server 必须跟随 client 的 preferred。→ Task 9 `TestQUICPairMigratesRelayDirectRelay`，Task 10 `TestQUICModeDirectFallbackToRelay`

---

### Task 1: 配置面：transport、QUIC 参数、CLI

**Files:**
- Modify: `p2p/config.go`
- Modify: `p2p/errors.go`
- Modify: `p2p/internal/host/apply.go`
- Modify: `p2p/internal/host/host.go`
- Modify: `p2p/cmd/p2p/main.go`
- Test: `p2p/internal/host/config_test.go`（追加）
- Test: `p2p/cmd/p2p/config_test.go`（追加）

**Interfaces:**
- Consumes: 现有 `p2p.Config`、`host.applyDefaults`、`applyTimeouts`。
- Produces:
  - `p2p.Config.Transport string`（`yaml:"transport,omitempty"`），空/`kcp`/`quic`。
  - `p2p.QUICConfig` 字段：`MTU int`、`RelayBatchBytes int`、`RelayFlush time.Duration`、`KeepAlive time.Duration`、`Idle time.Duration`、`HandshakeTimeout time.Duration`；`p2p.Config.QUIC *QUICConfig`。
  - `type transportMode uint8`；`const transportKCP transportMode = iota; transportQUIC`。
  - `type quicSettings struct { MTU int; RelayBatchBytes int; RelayFlush, KeepAlive, Idle, HandshakeTimeout time.Duration }`。
  - `func resolveTransport(cfg *p2p.Config) (transportMode, error)`。
  - `func resolveQUICSettings(c *p2p.QUICConfig) (quicSettings, error)`。
  - `p2p.ErrTransportUnsupported = errors.New("p2p: peer does not support the selected transport")`。
  - `engine.transport transportMode`、`engine.quicCfg quicSettings`（`quicID` 在 Task 3 加）。
  - CLI flag：`-transport kcp|quic`。

- [ ] **Step 1: 写失败测试 `TestTransportConfigDefaults` / `TestTransportConfigRejectsUnknown`**

在 `p2p/internal/host/config_test.go` 追加：

```go
func TestTransportConfigDefaults(t *testing.T) {
    cases := []struct{ in string; want transportMode }{
        {"", transportKCP}, {"kcp", transportKCP}, {"quic", transportQUIC},
    }
    for _, c := range cases {
        cfg := &p2p.Config{Transport: c.in, Derp: "ws://example"}
        got, err := resolveTransport(cfg)
        if err != nil || got != c.want { t.Fatalf("%q: got %v, %v", c.in, got, err) }
    }
}
func TestTransportConfigRejectsUnknown(t *testing.T) {
    if _, err := resolveTransport(&p2p.Config{Transport: "sctp", Derp: "ws://example"}); err == nil {
        t.Fatal("want error")
    }
}
```

再写 `TestQUICConfigValidation`：nil → 默认 `1200/32768/200µs/5s/15s/10s`；MTU 1199、batch 65537、Idle<=KeepAlive、Handshake<=0 各自返回错误；`transport=quic` 且 `Derp==""` 在 `New` 返回错误。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestTransportConfig|TestQUICConfig' -count=1"`

Expected: `undefined: resolveTransport` / `undefined: transportMode`。

- [ ] **Step 3: 实现配置与校验**

在 `p2p/config.go` 加字段/`QUICConfig`。在 `p2p/errors.go` 加 `ErrTransportUnsupported`。在 `p2p/internal/host/apply.go` 加 `resolveTransport`、`resolveQUICSettings` 和默认值（1200、32768、200µs、5s、15s、10s）；在 `host.New` 里调用，设置 `h.engine.transport`/`h.engine.quicCfg`；`transport=quic` 且 `cfg.Derp==""` 返回 `fmt.Errorf("p2p: transport quic requires derp mode")`。不创建 QUIC 行为，仅配置。

- [ ] **Step 4: 加 CLI flag 与 YAML 测试**

在 `p2p/cmd/p2p/main.go` 加 `transport := flag.String("transport", "kcp", "data plane: kcp or quic")`，并在 `set["transport"]` 时赋值。在 `p2p/cmd/p2p/config_test.go` 加 `TestConfigTransportYAML`：`transport: quic` + `quic: {mtu: 1400}` 能解析到 `p2p.Config.Transport/QUIC.MTU`。

- [ ] **Step 5: 跑测试与全包回归**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestTransportConfig|TestQUICConfig' -count=1 && GOWORK=off go test ./cmd/p2p/ -count=1"`

Expected: PASS。

- [ ] **Step 6: Commit（仅用户要求时）**

```bash
git -C p2p add config.go internal/host/apply.go internal/host/host.go cmd/p2p/main.go internal/host/config_test.go cmd/p2p/config_test.go
git -C p2p commit -m "feat: add transport mode and quic config"
```

---

### Task 2: caps TLV codec（`[caps][tlvVersion][TLV]`）

**Files:**
- Create: `p2p/internal/host/caps.go`
- Create: `p2p/internal/host/caps_test.go`
- Modify: `p2p/internal/host/direct.go`（`caps` 常量、`e.caps`、`sendCaps`、`announceDirect`、`addCaps`、`capNames`）
- Modify: `p2p/internal/host/engine.go`（`handleControl` 的 ctrlCaps 分支）

**Interfaces:**
- Consumes: 现有 `capsIPv6`/`capsNoDirect`、`directConn.peerCaps`、`e.priv.SealTo`/`OpenFrom`、`e.sendControl`。
- Produces:
  - `const capsQUIC uint8 = 1 << 3`。
  - `const capsTLVVersion1 = 1`、`const capsTLVQUIC = 0x01`。
  - `type quicCaps struct { Version uint8; Fingerprint [32]byte; BatchVersion uint8 }`。
  - `type capsInfo struct { Bits uint8; QUIC *quicCaps }`。
  - `func encodeCaps(info capsInfo) []byte`：`QUIC==nil` 时返回 `[]byte{info.Bits}`；否则 `[bits][1][0x01][34][version][fp][batch]`。
  - `func decodeCaps(b []byte) (capsInfo, error)`：len 0 错误；len 1 只返回 bits；`b[1]` 未知返回 bits + `errUnsupportedCapsVersion`；TLV 截断/长度非法返回 bits + error；未知 TLV 忽略；重复 QUIC TLV 后者覆盖。
  - `func (e *engine) caps() capsInfo`（替换现有 `func (e *engine) caps() uint8`）。
  - `func (e *engine) sendCaps(peer derpclient.PublicKey, info capsInfo) error`。
  - `func (dc *directConn) addCaps(info capsInfo)`（替换 `addCaps(bits uint8)`）。
  - `func (dc *directConn) peerQUICInfo() (quicCaps, bool)`（受 `dc.mu`）。

- [ ] **Step 1: 写失败测试**

`p2p/internal/host/caps_test.go`：

```go
func TestCapsEncodeLegacy(t *testing.T) {
    if got := encodeCaps(capsInfo{Bits: capsIPv6}); !bytes.Equal(got, []byte{capsIPv6}) {
        t.Fatalf("legacy caps = % x", got)
    }
}
func TestCapsRoundTripQUIC(t *testing.T) {
    fp := [32]byte{1, 2, 3}
    in := capsInfo{Bits: capsIPv6 | capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: fp, BatchVersion: 1}}
    out, err := decodeCaps(encodeCaps(in))
    if err != nil || out.Bits != in.Bits || out.QUIC == nil || out.QUIC.Fingerprint != fp {
        t.Fatalf("round trip: %+v %v", out, err)
    }
}
func TestCapsDecodeUnknownTLV(t *testing.T) { /* [caps][1][0x7f][0][0] -> bits, no err */ }
func TestCapsDecodeMalformedTLV(t *testing.T) { /* truncated length -> bits returned, err != nil, QUIC nil */ }
func TestCapsQUICLatestFingerprintWins(t *testing.T) {
    dc := &directConn{}
    dc.addCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{1}}})
    dc.addCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{2}}})
    got, ok := dc.peerQUICInfo()
    if !ok || got.Fingerprint != [32]byte{2} { t.Fatalf("got %+v ok=%v", got, ok) }
}
```

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestCaps' -count=1"`

- [ ] **Step 3: 实现 `caps.go` 并接入 `direct.go`**

`encodeCaps`/`decodeCaps` 按上面的字节布局实现；`e.caps()` 改为返回 `capsInfo`（Task 2 只带 bits；Task 3 再把 QUIC TLV 加进去）；`sendCaps`/`announceDirect`/`punch` 的调用点改成 `capsInfo`；`handleControl` 的 `ctrlCaps` 分支用 `decodeCaps`，把 `capsInfo` 传给 `addCaps`；`addCaps` 保留 bit OR 语义，但 `peerQUIC` 每次合法 QUIC TLV **覆盖**（latest-wins）。规则：bit 未置位 → `peerQUIC=nil`；bit 置位但 TLV 缺失/非法 → `peerQUIC=nil`。

- [ ] **Step 4: 跑 caps 与 direct 回归**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestCaps|TestDirect' -count=1"`

Expected: PASS（KCP 模式 caps 仍是 1 字节，现有测试不变）。

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/caps.go internal/host/caps_test.go internal/host/direct.go && git -C p2p commit -m "feat: add caps tlv codec for quic"`

---

### Task 3: QUIC TLS identity 与双向 pinning

**Files:**
- Create: `p2p/internal/host/quic_tls.go`
- Create: `p2p/internal/host/quic_tls_test.go`
- Modify: `p2p/internal/host/engine.go`（新增 `quicID *quicIdentity` 字段；`host.New` 在 QUIC 模式生成）

**Interfaces:**
- Consumes: `crypto/ed25519`、`crypto/tls`、`crypto/x509`、`crypto/sha256`。
- Produces:
  - `const quicALPN = "p2p-quic/1"`。
  - `type quicIdentity struct { cert tls.Certificate; fp [32]byte }`。
  - `func newQUICIdentity() (*quicIdentity, error)`。
  - `func (id *quicIdentity) fingerprint() [32]byte`。
  - `func quicTLSConfig(id *quicIdentity, peerFP [32]byte, server bool) *tls.Config`。
  - `func pinFingerprint(want [32]byte) func([][]byte, [][]*x509.Certificate) error`。
  - `engine.quicID *quicIdentity`（仅 QUIC 模式非 nil）。

- [ ] **Step 1: 写失败测试**

`p2p/internal/host/quic_tls_test.go`：

```go
func TestQUICIdentityFingerprint(t *testing.T) {
    id, err := newQUICIdentity(); if err != nil { t.Fatal(err) }
    sum := sha256.Sum256(id.cert.Certificate[0])
    if id.fingerprint() != sum { t.Fatal("fingerprint != sha256(DER)") }
}
func TestQUICTLSMutualPinning(t *testing.T) {
    a, _ := newQUICIdentity(); b, _ := newQUICIdentity()
    // net.Pipe + tls.Server(quicTLSConfig(b,b.fp,true)) / tls.Client(quicTLSConfig(a,a.fp,false))
    // both handshakes complete; NextProtos contains quicALPN.
}
func TestQUICTLSRejectsWrongFingerprint(t *testing.T) { /* client uses wrong peerFP -> Handshake error */ }
func TestQUICTLSRequiresClientCert(t *testing.T) {
    // server config requires client cert; anonymous client -> Handshake error.
}
func TestQUICTLSALPN(t *testing.T) { /* mismatched NextProtos -> handshake error */ }
func TestCapsIncludesQUICFingerprint(t *testing.T) {
    // e := &engine{transport: transportQUIC, quicID: id}
    // ci := e.caps(); ci.QUIC != nil && ci.QUIC.Fingerprint == id.fp
}
```

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestQUICTLS|TestQUICIdentity' -count=1"`

- [ ] **Step 3: 实现 `quic_tls.go`**

Ed25519 自签证书：随机 serial、CN=base64 公钥、NotBefore -1h、NotAfter +365d、KeyUsageDigitalSignature、ExtKeyUsageServerAuth+ClientAuth。`quicTLSConfig`：`Certificates`、`NextProtos`、client 设 `InsecureSkipVerify: true`，server 设 `ClientAuth: tls.RequireAnyClientCert`；两端 `VerifyPeerCertificate: pinFingerprint(peerFP)`。`pinFingerprint` 校验 `len(rawCerts)>0` 且 `sha256(rawCerts[0])==want`。

- [ ] **Step 4: 接入 `host.New`**

在 `host.New` 的 DERP 分支：若 `transport==transportQUIC`，`h.engine.quicID, err = newQUICIdentity()`；失败返回错误。KCP 模式不生成。更新 `e.caps()`：`transport==transportQUIC && quicID != nil` 时把 `QUIC` TLV（版本 1、FP、batch version 1）填进 `capsInfo`。

- [ ] **Step 5: 跑测试与 KCP 回归**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestQUICTLS|TestQUICIdentity|TestKCP' -count=1"`

- [ ] **Step 6: Commit（仅用户要求时）**

`git -C p2p add internal/host/quic_tls.go internal/host/quic_tls_test.go internal/host/engine.go internal/host/host.go && git -C p2p commit -m "feat: add quic tls identity and pinning"`

---

### Task 4: `multiPathConn` + 零长度 CID

**Files:**
- Create: `p2p/internal/host/quic_multipath.go`
- Create: `p2p/internal/host/quic_multipath_test.go`
- Modify: `p2p/go.mod` / `p2p/go.sum`（加 `github.com/quic-go/quic-go v0.63.0`）

**Interfaces:**
- Consumes: `quic.ConnectionIDGenerator`、`quic.ConnectionIDFromBytes`、`net.PacketConn`。
- Produces:
  - `const quicPathRelay = "relay"`、`quicPathDirect = "direct"`。
  - `type quicPathAddr struct { name string; addr netip.AddrPort }`，实现 `net.Addr`；`String()` 为 `"relay"` 或 `"direct:<addr>"`。
  - `type quicUnderlay struct { name string; addr net.Addr; pc net.PacketConn }`。
  - `type quicRole uint8`；`quicRoleClient`、`quicRoleServer`。
  - `func newMultiPathConn(role quicRole) *multiPathConn`。
  - `func (c *multiPathConn) addUnderlay(u quicUnderlay)`（同名替换；先停旧 reader，旧 reader error 不透传）。
  - `func (c *multiPathConn) removeUnderlay(name string)`。
  - `func (c *multiPathConn) setPreferred(name string)` / `func (c *multiPathConn) preferredPath() string`。
  - `net.PacketConn` 方法：`ReadFrom`、`WriteTo`、`Close`、`LocalAddr`、`SetDeadline`、`SetReadDeadline`、`SetWriteDeadline`。
  - `type zeroCIDGenerator struct{}`，实现 `ConnectionIDLen() int { return 0 }` 与 `GenerateConnectionID() (quic.ConnectionID, error)`。

- [ ] **Step 1: 写失败测试（fake `net.PacketConn`）**

`quic_multipath_test.go` 用一个 `pipePacketConn`（两个 channel + 固定 `net.Addr`）做 underlay。至少：

```go
func TestMultiPathClientPreference(t *testing.T) {
    // relay + direct underlay; client setPreferred(direct); WriteTo -> direct channel receives.
    // setPreferred(relay) -> relay channel receives.
}
func TestMultiPathServerRoutesByAddr(t *testing.T) {
    // server WriteTo(addr=directPathAddr) -> direct channel; relay addr -> relay channel.
}
func TestMultiPathDeadlineWake(t *testing.T) {
    // block ReadFrom; SetReadDeadline(time.Now()) returns os.ErrDeadlineExceeded promptly.
}
func TestMultiPathReplaceUnderlayIgnoresOldError(t *testing.T) {
    // replace "direct"; close old pc; ReadFrom must keep serving relay/new direct, no error.
}
func TestZeroCIDGenerator(t *testing.T) {
    if zeroCIDGenerator{}.ConnectionIDLen() != 0 { t.Fatal("want zero length") }
    id, err := zeroCIDGenerator{}.GenerateConnectionID()
    if err != nil || id.Len() != 0 { t.Fatalf("id=%v err=%v", id, err) }
}
```

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestMultiPath|TestZeroCID' -count=1"`

- [ ] **Step 3: 实现 `quic_multipath.go`**

实现 fan-in reader、client preferred 写、server addr 路由、`deadlineCh` 唤醒、underlay 替换/删除、有界队列（4096）+ drop 计数。`addUnderlay` 同名替换时先关闭旧 underlay 并标记其 reader 退出；旧 reader 的 error 只用于内部退出，不投递给 `ReadFrom`。`Close` 关闭所有 underlay。

- [ ] **Step 4: 加依赖并跑测试**

`bash -lc "cd p2p && GOWORK=off go mod tidy && GOWORK=off go test ./internal/host/ -run 'TestMultiPath|TestZeroCID' -count=1"`

Expected: PASS。

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add go.mod go.sum internal/host/quic_multipath.go internal/host/quic_multipath_test.go && git -C p2p commit -m "feat: add quic multi-path packet conn"`

---

### Task 5: relay batching codec + `relayQUICConn`

**Files:**
- Create: `p2p/internal/host/quic_relay.go`
- Create: `p2p/internal/host/quic_relay_test.go`

**Interfaces:**
- Consumes: `net.PacketConn`、`time.Timer`、`sync`。
- Produces:
  - `const quicRelayBatchBytes = 32 << 10`、`quicRelayFlush = 200 * time.Microsecond`、`quicRelayBatchVersion = 1`。
  - `func encodeQUICBatch(packets [][]byte) []byte`：`[uint16 len][packet]...`。
  - `func decodeQUICBatch(payload []byte) ([][]byte, error)`：截断/长度非法返回错误；合法返回切片（数据复制）。
  - `func newRelayQUICConn(in <-chan []byte, send func([]byte) error, closeFn func() error) *relayQUICConn`。
  - `relayQUICConn` 实现 `net.PacketConn`：`ReadFrom` 从 `in` 取一个 DERP data payload，拆包逐个返回；`WriteTo` 入 batching 队列；`Close` 停止 sender 并调用 `closeFn` 一次。
  - `relayQUICConn` 字段：`batches`, `packets`, `drops`（原子计数，供 Status/日志）。

- [ ] **Step 1: 写失败测试**

```go
func TestQUICBatchRoundTrip(t *testing.T) {
    in := [][]byte{{1,2}, {3}}
    out, err := decodeQUICBatch(encodeQUICBatch(in))
    if err != nil || !reflect.DeepEqual(out, in) { t.Fatalf("%v %v", out, err) }
}
func TestQUICBatchRejectsTruncated(t *testing.T) {
    if _, err := decodeQUICBatch([]byte{0, 5, 1, 2}); err == nil { t.Fatal("want error") }
}
func TestRelayQUICConnBatchesWrites(t *testing.T) {
    // WriteTo 3 small packets; sender should call send with one batch (or bounded count).
}
func TestRelayQUICConnFlush(t *testing.T) {
    // WriteTo one packet; send called within ~2*flush.
}
func TestRelayQUICConnDropsMalformed(t *testing.T) {
    // in <- truncated payload; ReadFrom must return the next valid packet, not the malformed one.
}
```

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestQUICBatch|TestRelayQUICConn' -count=1"`

- [ ] **Step 3: 实现 `quic_relay.go`**

Sender goroutine：`WriteTo` 把 packet 复制进待发队列；达到 `quicRelayBatchBytes` 或 `quicRelayFlush` 时 `encodeQUICBatch` 并调用 `send`；send 错误计数但不阻塞。Reader：`ReadFrom` 先取已拆队列；否则从 `in` 取 payload，`decodeQUICBatch`；malformed 计数并继续。`Close` 幂等：close stop channel、等待 sender、调用 `closeFn`。

- [ ] **Step 4: 跑测试与 race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestQUICBatch|TestRelayQUICConn' -count=1"`

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/quic_relay.go internal/host/quic_relay_test.go && git -C p2p commit -m "feat: add quic relay batching"`

---

### Task 6: `peerConn` data sink（KCP 行为不变）

**Files:**
- Modify: `p2p/internal/host/engine.go`
- Test: `p2p/internal/host/engine_test.go`（追加）
- Test: 现有 `internal/host` 全包回归

**Interfaces:**
- Consumes: 现有 `pump`、`peerConn.deliverInbound`、`peerConn.ensureSession`、`peerConn.Write`。
- Produces:
  - `peerConn.dataSink atomic.Pointer[func([]byte)]`（或受 `pc.mu` 保护的 `dataSink func([]byte)`；二选一，保持 hot path 无 `pc.mu`）。
  - `func (pc *peerConn) setDataSink(sink func([]byte))`。
  - `func (pc *peerConn) deliverData(pkt []byte)`：sink 非 nil 时直接调用（sink 必须非阻塞）；否则走现有 `ensureSession(true,false)` + `deliverInbound`。
  - `pump` 的 `frameData` 分支改为 `pc.deliverData(pkt)`。

- [ ] **Step 1: 写失败测试**

`TestPeerConnDataSinkBypassesKCP`：创建一个 `peerConn`（不建真实 DERP），设置一个记录 payload 的 sink；调用 `deliverData([]byte{1})`，断言 sink 收到；断言 `pc.sess == nil`（没有建 KCP session）。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run TestPeerConnDataSink -count=1"`

- [ ] **Step 3: 重构 `pump`/`peerConn`**

把 `pump` 里 `ensureSession` + `deliverInbound` 的逻辑移入 `deliverData`；`pump` 只做 `pc.lastFrameAt` 和 `pc.deliverData(pkt)`。KCP 默认 sink 为 nil，走原分支。确保 `deliverData` 在 sink 调用时不持锁，sink 内不能阻塞。

- [ ] **Step 4: 跑全包回归**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -count=1"`

Expected: PASS（这是 KCP 行为的回归门）。

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/engine.go internal/host/engine_test.go && git -C p2p commit -m "refactor: add peerConn data sink"`

---

### Task 7: `quicPair` over relay（建连、stream、accept、close）

**Files:**
- Create: `p2p/internal/host/quic.go`
- Create: `p2p/internal/host/quic_test.go`
- Create: `p2p/internal/host/quic_testutil_test.go`（in-memory relay `net.PacketConn` 对，测试用）

**Interfaces:**
- Consumes: Task 3 `quicIdentity`/`quicTLSConfig`、Task 4 `multiPathConn`/`zeroCIDGenerator`/`quicPathAddr`、Task 5 `relayQUICConn`。
- Produces:
  - `type quicPair struct { e *engine; peer derpclient.PublicKey; role quicRole; mp *multiPathConn; tr *quic.Transport; conn *quic.Conn; ln *quic.Listener; onStream func(net.Conn); cancel context.CancelFunc; ... }`。
  - `func newQUICPair(e *engine, peer derpclient.PublicKey, role quicRole, tlsCfg *tls.Config, qcfg *quic.Config, onStream func(net.Conn)) *quicPair`。
  - `func (p *quicPair) addRelayUnderlay(pc net.PacketConn) error`（加入 `mp`）。
  - `func (p *quicPair) establish(ctx context.Context) error`：建 `quic.Transport{Conn: mp, ConnectionIDGenerator: zeroCIDGenerator{}}`；client `Dial(ctx, relayAddr, tlsCfg, qcfg)`；server `Listen` + `Accept`；启动 `acceptStreams`。
  - `func (p *quicPair) openStream(ctx context.Context) (net.Conn, error)`。
  - `func (p *quicPair) acceptStreams()`。
  - `func (p *quicPair) close()`。
  - `func (p *quicPair) pathName() string`。
  - `type quicStreamConn struct { *quic.Stream; local, remote net.Addr }`，实现 `net.Conn`；`Close` 先 `CancelRead(0)` 再 `Stream.Close()`。

- [ ] **Step 1: 写失败测试 `TestQUICPairRelayEcho`**

用 `quic_testutil_test.go` 的 `newPacketPipe()` 创建两端 `net.PacketConn`；两个 `multiPathConn` 都加 relay underlay；`newQUICPair` client/server；`establish`；client `openStream` 写 "hello"；server `onStream` 读并回 "world"；断言收到。TLS 用两个 `newQUICIdentity()` 互相 pin。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run TestQUICPairRelayEcho -count=1"`

- [ ] **Step 3: 实现 `quic.go`**

`establish` 的 client/server 分支；`quic.Config` 由 Task 1 的 `quicSettings` 转成：`HandshakeIdleTimeout`、`MaxIdleTimeout`、`KeepAlivePeriod`、`InitialPacketSize`、`DisablePathMTUDiscovery`、`MaxIncomingStreams`、`MaxIncomingUniStreams`。`quicStreamConn` 包装。`acceptStreams` 循环 `AcceptStream(p.ctx)`，调用 `onStream`，流结束/关闭时退出。

- [ ] **Step 4: 加 `TestQUICPairCloseUnblocksAccept`**

关闭 client 连接，server 的 `AcceptStream` 必须返回错误、`acceptStreams` 退出，不能挂住。

- [ ] **Step 5: 跑测试与 race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestQUICPair' -count=1"`

- [ ] **Step 6: Commit（仅用户要求时）**

`git -C p2p add internal/host/quic.go internal/host/quic_test.go internal/host/quic_testutil_test.go && git -C p2p commit -m "feat: add quic pair over relay"`

---

### Task 8: Engine QUIC mode（caps 交换、relay 建连、OpenStream/Accept）

**Files:**
- Modify: `p2p/internal/host/engine.go`
- Modify: `p2p/internal/host/host.go`
- Modify: `p2p/internal/host/server.go`
- Test: `p2p/internal/host/quic_engine_test.go`（新建）
- Test: 现有 `internal/host` 全包回归

**Interfaces:**
- Consumes: Task 2 `capsInfo`/`decodeCaps`、Task 3 `quicIdentity`、Task 7 `quicPair`。
- Produces:
  - `engine.transport transportMode`、`engine.quicCfg quicSettings`、`engine.quicID *quicIdentity`。
  - `engine.quicMu sync.Mutex`、`engine.quics map[derpclient.PublicKey]*quicPair`。
  - `func (e *engine) ensureTransport(peer derpclient.PublicKey) (transportMode, error)`：QUIC 模式下创建/取 pair、发 caps、等 peer caps（`capsReplyTimeout` 3s）、`establish`；KCP 模式返回 `transportKCP`（不建 session）。
  - `func (e *engine) getQUIC(peer) *quicPair`。
  - `func (e *engine) setPeerCaps(peer, capsInfo)`（per-peer caps 存储 + 唤醒等待者）。
  - `func (e *engine) maybeStartQUIC(peer)`（`handleControl(ctrlCaps)` 触发；非阻塞）。
  - `func (e *engine) quicPairFor(peer, role) *quicPair`。
  - `handleControl` 的 `ctrlCaps` 分支调用 `decodeCaps`、`addCaps`、`e.maybeStartQUIC(src)`；`ctrlSecure` 在 QUIC 模式直接忽略。
  - `OpenStream`：`e.transport==transportQUIC` 时 `ensureTransport` + `pair.openStream`；否则现有 KCP 路径。
  - `pump`：QUIC 模式下 `frameData` 在 pair 已建立时交给 `pair.deliverRelay(pkt)`（`relayQUICConn` 的 `in` channel），不调用 `ensureSession`；pair 尚未建立时 `maybeStartQUIC(src)` 并丢弃该 data（控制帧会继续驱动握手）；KCP 模式不变。
  - `quicPair.deliverRelay(pkt []byte)`：非阻塞投递到 `relayQUICConn` 的 `in`。
  - `host.New` 设置 `engine.transport/quicCfg/quicID`；`server.status`/`peerTransports` 在 Task 12 扩展。

- [ ] **Step 1: 写失败测试 `TestQUICModeOpensTunnelOverRelay`**

用现有 fake DERP server 启动两个 engine（参考 `engine_test.go`/`direct_test.go` 的 `startEngines` 形状）；给两个 engine 设置 `transport=transportQUIC`、`quicCfg=default settings`、`quicID`；互相 `OpenStream`，断言 echo 成功；断言两侧 `PeerDiagnostic.Transport == "quic"`（Task 12 前可先断言 `engine.transport`）。同时断言没有 `relayKCPPair`（`len(e.relayKCPs)==0`）。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run TestQUICModeOpensTunnelOverRelay -count=1"`

- [ ] **Step 3: 实现 engine 集成**

`ensureTransport` 的 caps 等待用一个 per-peer `capsWait` channel/`sync.Cond`；`handleControl` 收到 caps 时写入并唤醒。`OpenStream` 分支、`pump` 分支、`maybeStartQUIC`（server 入站 caps 时启动 `Listen`）。QUIC 模式下 `pump` 不调用 `pc.ensureSession`；`pc.setDataSink` 不需要，`pair.deliverRelay` 直接投递。`ctrlSecure`/`ctrlSecure` 的 secure 会话在 QUIC 模式下不创建。

- [ ] **Step 4: 跑测试与 KCP 回归**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestQUICMode|TestKCP' -count=1"`

Expected: PASS。

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/engine.go internal/host/host.go internal/host/server.go internal/host/quic_engine_test.go && git -C p2p commit -m "feat: establish quic over relay"`

---

### Task 9: `directPacketConn` + `quicPair` relay↔direct 迁移

**Files:**
- Create: `p2p/internal/host/quic_direct.go`
- Create: `p2p/internal/host/quic_direct_test.go`
- Modify: `p2p/internal/host/quic.go`
- Modify: `p2p/internal/host/directunderlay.go`（如需要，加 `peerAddr()` 访问器）

**Interfaces:**
- Consumes: 现有 `directUnderlay`（`readFrom`/`writeTo`/`sendHeartbeat`/`hbLive`/`close`）、`newDirectUnderlayToken`、Task 4 `multiPathConn`。
- Produces:
  - `type directPacketConn struct { u *directUnderlay }`，实现 `net.PacketConn`：`ReadFrom` 循环吞掉 `os.ErrDeadlineExceeded`；`WriteTo` 调 `u.writeTo`；`LocalAddr`/`RemoteAddr` 返回 peer 地址；`Close` 调 `u.close`。
  - `func (p *quicPair) addDirect(sock *net.UDPConn, peerAddr netip.AddrPort, token [seedTokenLen]byte) error`：`u := newDirectUnderlayToken(...)`；`mp.addUnderlay(quicUnderlay{name: quicPathDirect, addr: quicPathAddr{name: quicPathDirect, addr: peerAddr}, pc: &directPacketConn{u}})`；client `mp.setPreferred(quicPathDirect)`；记录 `p.directSock = sock`（受 `p.mu`）。
  - `func (p *quicPair) removeDirect(sock *net.UDPConn)`：只有 `p.directSock == sock` 才执行（旧 re-punch 的延迟 retire 不得拆掉新 underlay）；client 若 preferred==direct 则切 relay；`mp.removeUnderlay(quicPathDirect)`；清 `p.directSock`；关闭 socket（幂等）。

- [ ] **Step 1: 写失败测试 `TestDirectPacketConnFiltersAndEchoes`**

用两个 UDP socket（loopback）；一个 `directUnderlay`；`directPacketConn.ReadFrom` 只返回 peer 的包，seed magic 被回显/过滤；`os.ErrDeadlineExceeded` 不返回给调用者。

- [ ] **Step 2: 写失败测试 `TestQUICPairMigratesRelayDirectRelay`（产品化 migration spike）**

用 `quic_testutil_test.go` 的 relay pipe + 两个 UDP socket 对；client/server `quicPair`；建立 relay 上的双向 counter stream；`addDirect` 两侧；client preferred direct → 断言 server `conn.RemoteAddr()` 变为 `direct:<addr>`；切回 relay → 变回 relay；再加新 direct → 再变 direct；全程序号流无丢/无乱序。至少 500 条记录/方向。

- [ ] **Step 3: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestDirectPacketConn|TestQUICPairMigrates' -count=1"`

- [ ] **Step 4: 实现 `quic_direct.go` + `quicPair` 方法**

注意：`directUnderlay.readFrom` 的 1s deadline 是给 KCP pair 的 idle tick；`directPacketConn` 必须内部吞掉 timeout，不能透传给 quic-go。`removeDirect` 关闭旧 underlay 时，旧 reader 的错误不能进入 `multiPathConn.ReadFrom`。

- [ ] **Step 5: 跑测试与 race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestDirectPacketConn|TestQUICPairMigrates' -count=1"`

- [ ] **Step 6: Commit（仅用户要求时）**

`git -C p2p add internal/host/quic_direct.go internal/host/quic_direct_test.go internal/host/quic.go internal/host/directunderlay.go && git -C p2p commit -m "feat: add quic direct path migration"`

---

### Task 10: Engine direct hook + punch 集成

**Files:**
- Modify: `p2p/internal/host/direct.go`
- Modify: `p2p/internal/host/engine.go`
- Modify: `p2p/internal/host/quic.go`
- Test: `p2p/internal/host/quic_direct_engine_test.go`（新建）
- Test: 现有 `direct_test.go` 回归

**Interfaces:**
- Consumes: Task 9 `quicPair.addDirect/removeDirect`、现有 `directConn.markUp/teardown/underlayDead/punch`。
- Produces:
  - `func (e *engine) installDirect(peer derpclient.PublicKey, sock *net.UDPConn, addr netip.AddrPort, token [seedTokenLen]byte)`：KCP 模式走现有 `registerDirectUnderlay`；QUIC 模式走 `pair.addDirect`。
  - `func (e *engine) retireDirect(peer derpclient.PublicKey, sock *net.UDPConn)`：KCP 模式走 `pair.clearDirectUnderlayIf`；QUIC 模式走 `pair.removeDirect`。
  - `directConn.markUp` 调 `e.installDirect`；`teardown`/`underlayDead` 调 `e.retireDirect`。
  - `punch()` 里 `relayKCPPairGet(...).noteSeed(...)` 改为 `e.noteSeed(peer, ...)`；QUIC 模式 no-op 或 QUIC 计数器。

- [ ] **Step 1: 写失败测试 `TestQUICModeDirectPunch`**

复用现有 `TestDirectPunchRoundTrip` 的两 engine/fake DERP/STUN 设置，但 `transport=quic`；断言：
- 双侧 direct 状态 up；
- `quicPair.pathName()=="direct"`；
- 通过 direct 打开流/echo 成功；
- `PeerDiagnostic.DirectTransport=="quic"`（Task 12 前先断言内部字段）。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run TestQUICModeDirectPunch -count=1"`

- [ ] **Step 3: 实现 hook 与 directConn 改动**

`markUp` 里原先 `registerDirectUnderlay` 的调用改为 `e.installDirect`；`teardown`/`underlayDead` 的 `pair.clearDirectUnderlay` 改为 `e.retireDirect`；保留 `dc.sock`/`sessAt`/state 语义。QUIC 模式下 `punch` 不调用 `relayKCPPairGet` 的 nil 解引用。

- [ ] **Step 4: 跑 direct 回归与 race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestDirect|TestQUICModeDirectPunch' -count=1"`

Expected: PASS（KCP direct 测试全部不变）。

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/direct.go internal/host/engine.go internal/host/quic.go internal/host/quic_direct_engine_test.go && git -C p2p commit -m "feat: wire quic direct punch"`

---

### Task 11: 失败处理：direct 掉线、relay 断线、QUIC 重建

**Files:**
- Modify: `p2p/internal/host/engine.go`
- Modify: `p2p/internal/host/quic.go`
- Modify: `p2p/internal/host/relaykcp.go`（仅 relay 断线路径的 QUIC 分支）
- Test: `p2p/internal/host/quic_failure_test.go`（新建）

**Interfaces:**
- Consumes: Task 10 hooks、现有 `directUnderlayIdle`/heartbeat、`peerConn` relay 生命周期、`engine.reconnectRelay`/`teardown`。
- Produces:
  - `func (p *quicPair) relayDown()` / `func (p *quicPair) relayUp(pc net.PacketConn) error`：替换 relay underlay，不杀 QUIC 连接。
  - `func (p *quicPair) onConnClosed(err error)`：通知 engine；engine 丢弃 `quics[peer]`，下次 `OpenStream` 重建（仍 QUIC）。
  - `engine` relay teardown 分支：`transport==transportQUIC` 时调用 `pair.relayDown()`；重连后 `pair.relayUp(newPC)`；不调用 `killSession`/`resetPeerSession` 的 KCP 逻辑。
  - direct 心跳判死路径：`retireDirect` + `preferred=relay` + re-punch；连接继续。

- [ ] **Step 1: 写失败测试**

- `TestQUICDirectLossFallsBackToRelay`：建立 QUIC relay+direct；关闭 direct socket/暂停 heartbeat；断言流继续，`pathName()=="relay"`，QUIC 连接未重建。
- `TestQUICRelayLossKeepsDirect`：direct 活着时断 relay；断言连接/流继续；relay 恢复后 underlay 加回。
- `TestQUICConnDeathRebuildsQUIC`：关闭 QUIC conn；断言下次 `OpenStream` 重建 QUIC（不是 KCP），`relayKCPs` 仍为空。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestQUICDirectLoss|TestQUICRelayLoss|TestQUICConnDeath' -count=1"`

- [ ] **Step 3: 实现失败路径**

relay 断线：QUIC 模式下不 `killSession`；`relayDown` 把 relay underlay 从 `mp` 移除/标记 down；direct 活着时连接继续。relay 恢复：用新的 `relayQUICConn` 替换 underlay，同一 `relayPathAddr`，QUIC 不感知路径变化。QUIC conn 关闭：`onConnClosed` 清 map；下次 open 重建。direct 掉线：client `setPreferred(relay)`、`removeDirect`、现有 re-punch backoff；server 跟随。

- [ ] **Step 4: 跑失败测试与全包 race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -run 'TestQUIC|TestDirect|TestRelay' -count=1"`

- [ ] **Step 5: Commit（仅用户要求时）**

`git -C p2p add internal/host/engine.go internal/host/quic.go internal/host/relaykcp.go internal/host/quic_failure_test.go && git -C p2p commit -m "feat: handle quic path and connection failures"`

---

### Task 12: Status / PeerDiagnostic / doctor / 日志

**Files:**
- Modify: `p2p/status.go`
- Modify: `p2p/internal/host/engine.go`（`peerTransports`/`peerDiagnostics`/`status`）
- Modify: `p2p/doctor/doctor.go`
- Test: `p2p/internal/host/quic_status_test.go`（新建）
- Test: `p2p/doctor/doctor_test.go`（追加）

**Interfaces:**
- Consumes: Task 8/10/11 的 `engine.transport`、`engine.quics`、`quicPair.pathName()`、`quicPair.stats()`。
- Produces:
  - `p2p.QUICStats`：`Live bool`、`Role string`、`Path string`、`RTT time.Duration`、`Streams int`、`BytesSent uint64`、`BytesRcvd uint64`。
  - `PeerDiagnostic.Transport string`（`"kcp"`/`"quic"`）、`QUIC *QUICStats`、`DirectTransport string`、`TransportError string`。
  - `Status.Transport string`（`"kcp"`/`"quic"`；host 级）。
  - `func (p *quicPair) stats() p2p.QUICStats`（RTT 用 `conn.ConnectionStats().SmoothedRTT`；path 用 `pathName()`）。
  - `engine.peerTransports`/`peerDiagnostics` 在 QUIC 模式下用 `quicPair` 的 path/stats；`SessionState` 用 QUIC conn 状态；`RelayKCP` 为空。
  - 日志事件：`transport selected`、`transport error`、`quic handshake`、`quic path-change`、`quic underlay`、`quic conn closed`。
  - `p2p/doctor` 打印 `transport`、`quic path`、`quic rtt`、`transport error`（进程内 `p2p.Status` 调用）。

- [ ] **Step 1: 写失败测试 `TestPeerDiagnosticsReportsQUICStats`**

用两 engine QUIC 模式建立 peer；`Status.PeerDiagnostics[peer]` 断言 `Transport=="quic"`、`QUIC != nil`、`QUIC.Path` 为 relay/direct、`DirectTransport=="quic"`。KCP 模式断言 `Transport=="kcp"`、`QUIC==nil`。

- [ ] **Step 2: 写失败测试 `TestDoctorPrintsQUICTransport`**

构造 `p2p.Status{PeerDiagnostics: map[...]{...QUIC...}}`，调用 `doctor.Report`，断言输出含 `quic`/`path`/`rtt`；不要求 CLI gRPC doctor 显示。

- [ ] **Step 3: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ ./doctor/ -run 'TestPeerDiagnosticsReportsQUIC|TestDoctorPrintsQUIC' -count=1"`

- [ ] **Step 4: 实现 status/doctor/日志**

字段和渲染按 spec §8.12；gRPC proto 不变，`cmd/p2p/doctor` 不改。`Status.PeerTransports` 仍用 direct/derp；QUIC 细节只在进程内。

- [ ] **Step 5: 跑测试与全包回归**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ ./doctor/ -count=1"`

- [ ] **Step 6: Commit（仅用户要求时）**

`git -C p2p add status.go internal/host/engine.go internal/host/quic.go doctor/doctor.go internal/host/quic_status_test.go doctor/doctor_test.go && git -C p2p commit -m "feat: report quic transport status"`

---

### Task 13: 严格模式负例、多 peer 隔离、KCP 回归

**Files:**
- Test: `p2p/internal/host/quic_strict_test.go`（新建）
- Test: `p2p/internal/host/quic_multipeer_test.go`（新建）
- Test: 现有 `internal/host` 全包

**Interfaces:**
- Consumes: Task 8/10/11 的 engine QUIC 模式、caps、TLS。
- Produces: 无新生产接口；测试锁定严格互斥/no-fallback/隔离。

- [ ] **Step 1: `TestQUICModeRejectsKCPPeer`**

两个 engine，A `transport=quic`，B `transport=kcp`；A `OpenStream(B)` 返回 `ErrTransportUnsupported`（或包装后的可识别错误）；断言 A 的 `relayKCPs` 为空、B 仍正常 KCP。

- [ ] **Step 2: `TestQUICModeNoPinNoConnection`**

A QUIC，B QUIC 但 B 的 caps 不带合法 FP（测试直接构造 caps 或把 `quicID` 置 nil 让 `caps()` 不带 TLV）；A 的 `OpenStream` 失败；不建 KCP。

- [ ] **Step 3: `TestQUICModeMultiPeerIsolation`**

A 同时连 B、C（QUIC）；B/C 各自一个 Transport；关闭 B 的连接不影响 A-C；断言两个 `quicPair` 的 `tr` 指针不同、`mp` 不同。可选：B/C 的 relay underlay 数据不会路由到对方。

- [ ] **Step 4: 跑测试确认失败/通过**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run 'TestQUICModeRejectsKCPPeer|TestQUICModeNoPin|TestQUICModeMultiPeer' -count=1"`

- [ ] **Step 5: 全包 KCP 回归 + race**

`bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -count=1"`

Expected: PASS；KCP 现有测试全部绿。

- [ ] **Step 6: Commit（仅用户要求时）**

`git -C p2p add internal/host/quic_strict_test.go internal/host/quic_multipeer_test.go && git -C p2p commit -m "test: pin quic strict mode and multi-peer isolation"`

---

### Task 14: relay batching 集成、E2E 场景、文档

**Files:**
- Modify: `p2p/internal/host/engine.go`（QUIC relay sink 用 `relayQUICConn`；`frameData` 路由）
- Modify: `p2p/internal/host/quic.go`（`deliverRelay`/`relayUp` 的 batch 连接）
- Create: `p2p/tests/e2e/quic_test.go`（或扩展现有 e2e 场景）
- Modify: `p2p/tests/e2e/e2e_test.go`（新 scenario `quic-direct`）
- Modify: `p2p/docs/2026-10-29-quic-vs-kcp-smux-spike.md`（加实现状态）
- Test: `p2p/internal/host/quic_relay_integration_test.go`（新建）

**Interfaces:**
- Consumes: Task 5 `relayQUICConn`/batching、Task 8 pump、Task 9/10 direct、Task 11 failure。
- Produces:
  - `engine` 在 QUIC 模式下为每个 peer 创建 `relayQUICConn`，把 `in` 接到 `peerConn` 的 data sink，把 `send` 接到 `pc.Write`；`relayUp` 重建 batching conn。
  - E2E `quic-direct`：两个容器 + derper，`transport: quic`，验证 relay-only、direct 迁移、direct→relay 回落、双向数据。
  - 文档：实现状态、已知限制（单 relay、无 fallback、零 CID/每 peer Transport、1200 MTU）。

- [ ] **Step 1: 写失败测试 `TestQUICRelayBatchingIntegration`**

用 fake DERP data payload 队列 + `relayQUICConn`；发送多个小 QUIC packet，断言对端 `ReadFrom` 能逐个拆出；malformed payload 被丢弃且后续 payload 正常。断言 batch 数 < packet 数（batching 生效）。

- [ ] **Step 2: 跑测试确认失败**

`bash -lc "cd p2p && GOWORK=off go test ./internal/host/ -run TestQUICRelayBatchingIntegration -count=1"`

- [ ] **Step 3: 接入 pump 的 QUIC relay sink**

`peerConn` 的 QUIC data sink 是 `relayQUICConn` 的入队函数；`relayQUICConn.send` 调 `pc.Write`；`relayUp` 重建 `relayQUICConn`。控制帧仍走 `handleControl`。

- [ ] **Step 4: 加 E2E `quic-direct` 场景**

在 `p2p/tests/e2e` 里按 `derp-direct` 的形状加 `quic-direct`：两个 p2p 容器 + derper；`-transport quic`；断言 relay-only 流、direct 迁移、direct→relay 回落；用日志/Status 断路径。若 e2e 环境不具备 Docker，先写 scenario 并记录未跑。

- [ ] **Step 5: 全量验证**

```bash
bash -lc "cd p2p && GOWORK=off go vet ./... && GOWORK=off go test ./internal/host/ -count=1 && GOWORK=off go test ./doctor/ -count=1"
bash -lc "cd p2p && CGO_ENABLED=1 GOWORK=off go test -race ./internal/host/ -count=1"
```

E2E（若 Docker 可用）：`bash -lc "cd p2p/tests/e2e && go test -run TestQUICDirect -count=1 -v"`。

- [ ] **Step 6: 更新文档**

在 spike 报告加“实现状态（2026-10-29 design/plan）”，在设计文档 §13/§14 记录实现完成/未完成项；不把未验证的 E2E 说成通过。

- [ ] **Step 7: Commit（仅用户要求时）**

`git -C p2p add internal/host/engine.go internal/host/quic.go internal/host/quic_relay_integration_test.go tests/e2e/... docs/... && git -C p2p commit -m "feat: integrate quic relay batching and e2e"`

---

## Self-Review

- **Spec coverage:** G1 Task 1; G2 Task 7/8; G3 Task 5/9/10/14; G4 Task 2/3/7/8; G5 Task 8/13; G6 Task 2/3; G7 Task 12; G8 Task 9/10/11. Non-goals (no 0-RTT/datagram/MP aggregation/live switch/fallback/multi-DERP) are enforced by Task 1/8/13 tests and Task 3 config.
- **Step scan:** each task has a failing test, a run-fail step, implementation, a run-pass step, and a conditional commit. No "TBD"/"handle edge cases".
- **Type consistency:** `capsInfo`/`quicCaps` (Task 2), `quicIdentity` (Task 3), `multiPathConn`/`quicUnderlay` (Task 4), `relayQUICConn` (Task 5), `quicPair` (Task 7), `engine.ensureTransport` (Task 8), `installDirect`/`retireDirect` (Task 10), `p2p.QUICStats` (Task 12) are named consistently across tasks.
- **Review Focus coverage:** 1 Task 13; 2 Task 3/13; 3 Task 4/7/13; 4 Task 4/9; 5 Task 9/10.
- **Proportion:** This plan is mostly signatures/tests/commands; production code bodies are left to the implementer except where a specific algorithm (batch framing, zero-CID generator) needs exact values.
