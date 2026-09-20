# p2p:IPv6 直连支持 —— 实施计划

## Context(为什么做)

2026-09-12 的 NAT 调研把「IPv6 直连」列为覆盖率提升的第一名:双栈双方若都有全局 v6,**根本不需要打洞**——v6 通常不做地址转换,地址本身就可达;即便 CPE 有状态防火墙,地址也不变、只是被过滤,双方同时发包即可打开 pinhole。而对称 NAT/CGNAT 场景下打洞必失败、永远退 relay,正是上一阶段(direct/relay 统计)要量化的问题。

现在的直连路径是 **IPv4-only**:候选收集靠 STUN(v4 socket),拨号目标只从 `Is4()` 候选里选。本计划让 v6 成为一等候选族。

已核实的基础设施现状:

- `candidate` 就是 `netip.AddrPort`(direct.go:68),族无关。
- **`decodeCandidates` 已经支持 family 6**(16 字节,direct.go:640-644)——不用改。
- **kcp-go 也已族无关**:`kcp.NewConn4(convid, raddr net.Addr, block, d, p, ownConn, conn net.PacketConn)`,`raddr` 是 `net.Addr`。
- 因此 v4-only 的硬编码只剩 5 处:socket(`udp4`)、`ipv4Addrs` 过滤、`encodeCandidates` 族字节、`bindAddrFor`、以及 `--stun` 这个总开关。

## 已定的决策(不再讨论)

1. **v6 候选来自本地接口枚举**,不用 STUN——v6 无地址转换,本地地址即可达地址。
2. **v6 独立于 `--stun` 启用**:有可用 v6 候选就尝试直连,无需配置 STUN。
3. **同轮内换族重试**:首选族 seed 失败 → 立即用另一族重试同一轮。两族各用各的 socket,不违反 kcp「一 socket 一 session」约束;单向可达的 v6 会被 `seedHandshake` 挡住(它要求 own→peer→own 完整往返),**两侧同时判败 → 同时退到 v4 → 收敛**。跨轮降级记忆已否决(单侧 v6 坏时两侧选择会不一致)。
4. **能力协商**(而非「无应答就重发」):新增控制帧 kind,确认对端支持 v6 后才广播 v6 候选。

## 设计

### 候选收集

- **v4(保持原样,但改为可选)**:仅当 `e.stunAddr != ""` 时,`net.ListenUDP("udp4", bindAddrFor(e.stunAddr))` + `stun.Lookup` → `[localEP, pubEP]` 去重。**STUN 失败不再直接 `backoff()`**:若此时有 v6 候选,则本轮丢弃 v4 族(关 socket、记日志)继续走 v6。
- **v6(新)**:`localV6() []netip.Addr` —— 遍历 `net.Interfaces()`,保留 `Is6() && !IsLinkLocalUnicast() && !IsUnspecified() && !IsLoopback()`,去重。排序是唯一的策略点:**全局单播 → ULA**,便于日志与首轮选择可预期。
  - **排除 link-local**:`netip.AddrPort` 不携带 zone,`fe80::` 无法正确表达。
  - **排除 loopback**:`::1` 在真机上不可达对端,若纳入会让「本机无 v6 出口」时每轮白跑一次 v6 attempt。测试通过注入 seam 提供 `::1`(见下)。
  - 非空时绑**一个 `net.ListenUDP("udp6", &net.UDPAddr{})`(通配)**。通配是刻意的:任一被广播的地址都在同一端口可收,于是**拨号规则不需要「两侧选同一对」的约定**。`socket.LocalAddr()` 是 `[::]:port`,**不得作为候选广播**。
- `mine` 仍是单个 `[]candidate`(v4 在前,日志对齐)。
- `encodeCandidates`(direct.go:605)按 `c.Addr()` 的族写 `4`/`6`,分别 `As4()`/`As16()`;`decodeCandidates` 不动。

### 能力协商

- 新增 `ctrlCaps = 0x04`(direct.go:39-40 附近),载荷 sealed。
- **向后兼容已逐行核实**:`handleControl`(engine.go:461-494)是没有 `default` 的 switch,且 `OpenFrom` 在**每个 case 内部**——旧 host 收到 0x04 会静默落出,不报错、不碰 box、不改状态;帧格式 `[frameControl][kind][payload]` 本就任意 kind,无需改格式或版本号。
- 发送时机:在**首次要为该 peer 打洞时**发一次(`directConn` 创建处),并置一个「caps 已发」标记。
- 每 peer 存一个 `supportsV6 bool`(收到对端 `ctrlCaps` 才置真)。
- **未确认即保守**:`supportsV6 == false` 时只广播 v4 候选。于是:
  - 新-新:首轮可能还不知道 → 退 v4 一轮;此后走 v6。
  - 新-旧:永远无应答 → 持续 v4-only,**不浪费任何一轮**,且是 v4 直连而非 relay。
- 该机制可复用给以后的特性协商(本次只做 v6 一位)。

### 族选择与同轮回退(对称性论证)

顺序是**两个候选列表的纯函数**,两侧独立算、结果一致:

1. **v6 优先,当且仅当**:双方列表都含 v6 候选,且双方 caps 均已确认(我方的 `supportsV6` 与对端回执)。
2. 否则 v4(双方列表都含 v4)。

对称性:两侧各自计算的是**同一对**谓词 `(我方有 v6, 对端有 v6)`,与既有 hairpin 规则同构(那份设计文档已确立「对同一对值做比较,两侧结果必然一致」,docs/2026-09-09:132)。非对称情形:(a) 仅一侧有 v6 → 两侧都选 v4;(b) 都有 v6 但单向不可达 → `seedHandshake` 两侧同窗口判败 → 都退 v4;(c) 我方 v6 绑失败 → 我方不广播 v6 → 两侧都选 v4。

每族一次尝试:选目标 → `kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, sock)` → `seedHandshake(kcpConn, seedTimeout)`。失败则关掉该 KCP 连接(`ownConn=true` 会连带关掉该族 socket)并立即跑下一族;两族都失败才 `backoff()`。轮内**不重新交换候选**,两侧用相同超时执行相同序列。

- **拨号规则**:v6 取对端列表里**第一个 v6 候选**(通配绑使「不需要双方选同一对」);v4 保持既有 hairpin 规则(direct.go:422-425)。
- **socket 所有权**:一轮最多两个 socket(v4/v6),`keep` 布尔升级为「胜者 socket 交给 `markUp`,败者显式关闭」。
- **已知时序影响**:一轮最长 2×`seedTimeout`,可能超过 `punchWaitTimeout`——该次 `OpenStream` 会先走 relay,但打洞 goroutine 仍会完成,后续 stream 走直连(与今日慢打洞行为一致)。代码注释写明两族用**相同**的 `seedTimeout`。

### 门控变更

`Engine.maybeStartDirect`(direct.go:113)与 `punchAndWait`(direct.go:125)的早返回条件由 `e.stunAddr == ""` 改为「`e.stunAddr == ""` **且** 无 v6 候选」——即 v6 存在时无需 STUN 也尝试直连。

## 任务分解(每步独立可验证)

1. **codec 族化** —— `encodeCandidates`(direct.go:605)按族写 4/6。测:v4+v6 混合列表 encode→decode 往返(含端口与顺序);legacy 纯 v4 帧仍可解;未知族仍报错。
2. **`localV6()` + 注入 seam** —— 新增 `var localV6Addrs = localV6`(与 `TestMain` 里可调的时间变量同风格,direct_test.go:28)。测:排除 link-local/loopback/unspecified/4-in-6;跨网卡去重;排序全局→ULA。
3. **能力协商** —— `ctrlCaps` 常量 + 发送(首次打洞意图时)+ 每 peer `supportsV6` + `handleControl` 新增 case。测:收到 `ctrlCaps` 后 `supportsV6` 置真;**未知 kind 不改变任何状态**(模拟旧 host);caps 未确认时不广播 v6 候选。
4. **punch 重构** —— `punch()`(direct.go:340-470)按上面「候选收集 / 族选择 / 同轮回退 / socket 所有权」改造;新增 `v6Addrs(cands)` 紧邻 `ipv4Addrs`(direct.go:523);门控改 direct.go:113/:125。测见下。
5. **文档** —— `main.go:54` 的 `--stun` 帮助文案("empty disables direct" 已不成立)、`p2p/CLAUDE.md`(标志表 + Direct data plane 段 + `--stun` 语义)、`README.md` 与 `README.zh-CN.md` 的标志表、以及 `docs/2026-09-09-p2p-mutual-punch-design.md` 补一节附录(其拨号目标规则与「对 engine.go 零改动」的断言在本计划后不再成立)。

## 测试策略

仓库没有 `t.Skip`/`testing.Short` 惯例。v6 测试自守卫:探针 `net.ListenUDP("udp6", ::1)` 失败则跳过。复用既有脚手架:`relayServer`(engine_test.go:155,TCP/WS,族无关,可直接用)、`startFakeSTUN`(direct_test.go:40,udp4-only,**本次不需要 udp6 版**——v6 候选不走 STUN)、`newEngine`、`startEcho`、`roundTrip`、`waitFor`、`hasDirect`。

| 测试 | 断言 |
|---|---|
| `TestDirectV6NoSTUN` | 注入 `localV6Addrs` 返回 `::1`,`stunAddr` 留空 → 直连仍然建立(证明门控变更) |
| `TestDirectV6FallbackToV4` | 注入黑洞 v6(`2001:db8::1`)+ 正常 fake STUN → 直连建立且 `dc.peerAddr` 是 v4(证明同轮换族) |
| `TestDirectNoCandidateSourceRelayOnly` | 注入空 v6 + `stunAddr == ""` → `punchAttempts == 0`,relay 往返正常 |
| `TestCapsUnknownStaysV4` | 对端不回 `ctrlCaps` → 我方广播的候选里只有 v4;`supportsV6` 始终 false |
| `TestCapsUnknownKindIgnored` | 投递一个未知 kind 帧 → engine 状态不变(向后兼容回归) |
| `TestEncodeCandidatesFamily` | 混合族往返;legacy v4 帧兼容 |

`TestDirectV6FallbackToV4` 会真跑两次 `seedTimeout`;若耗时不可接受,在 `TestMain`(direct_test.go:28)里缩短 `seedTimeout`(注意两族必须用同一个值)。

## 验证

```bash
cd /config/workspace/go-gost/p2p
go build ./... && go vet ./...
GOWORK=off go build ./...          # 跨仓门禁
CGO_ENABLED=1 go test -race -p 1 ./...
```

> 本工作区注意:`go build` 输出经 RTK 改写,会出现假 "Success";必须在**同一行**里 `cd <module> && pwd`,并用 `/config/.go/bin/go ... > file 2>&1; echo exit=$?` 读真实退出码。

端到端(可选,复用既有 netns 流程):两个 host 在**同一主机**上跑 `::1` 直连验证;真跨机 v6 直连需要两条有全局 v6 的路径,视环境而定。

## 风险 / 已接受的取舍

1. **多宿主机首列 v6 不可达** → 该轮失败而非尝试下一个 v6。v1 接受(通配绑下换下一个候选需要多轮,收益小)。
2. **RFC 4941 临时地址轮换** → 长会话在地址过期时断开,靠既有 re-punch 恢复。接受。
3. **通配 v6 绑定** 扩大了接收面(本机所有 v6 地址同一端口),但候选仍需知晓 + seed 握手把关。接受。
4. **首轮退 v4** —— caps 未确认前保守只发 v4,新-新组合的首轮是 v4。接受(确定性优于省一轮)。
5. 若 `punchWaitTimeout` 在两族尝试间到期,首次 `OpenStream` 走 relay,后续走直连。接受并写入注释。

## 不做(YAGNI)

NAT66/前缀转换的 v6 STUN 探测、链路本地(zone)候选、多 v6 候选轮询、v6 候选的 PCP/UPnP 映射、以及把 caps 扩展成通用的特性协商框架(本次只放 v6 一位)。
