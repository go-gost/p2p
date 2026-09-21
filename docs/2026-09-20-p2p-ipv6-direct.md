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

1. **v6 候选取自单一出口地址**,不用 STUN——v6 无地址转换,绑定并广播该出口地址即可达,且发送源确定(kcp 严格源过滤要求「回包源 == 被拨候选」)。生产用 `detectV6Egress()` 做一次路由探测(向全局 v6 目标 `DialUDP`,不发包)取出口;无全局 v6 则不打 v6。
2. **v6 独立于 `--stun` 启用**:有可用 v6 候选就尝试直连,无需配置 STUN。
3. **同轮内换族重试**:首选族 seed 失败 → 立即用另一族重试同一轮。两族各用各的 socket,不违反 kcp「一 socket 一 session」约束;单向可达的 v6 会被 `seedHandshake` 挡住(它要求 own→peer→own 完整往返),**两侧同时判败 → 同时退到 v4 → 收敛**。跨轮降级记忆已否决(单侧 v6 坏时两侧选择会不一致)。
4. **能力协商作为前瞻接缝**(而非「无应答就重发」):新增 `ctrlCaps` 控制帧,sealed 能力位域,可重复广播、对端按位 OR——为将来的**破坏性**扩展留协商入口。**但 v6 不依赖它门控**:候选列表本身就是 in-band 的能力信号,族选择只看候选列表(见「族选择」)。依据:已核实 family 6 的 `decodeCandidates` 与 `ipv4Addrs` 过滤在 `v0.1.0`/`v0.2.0` 均已存在(`ecfb9d4` 同时含两个 tag),旧 host 收到 v6 候选只会解码后丢弃,不报错;故发送 v6 候选本就向后兼容,无需先确认。

## 设计

### 候选收集

- **v4(保持原样,但改为可选)**:仅当 `e.stunAddr != ""` 时,`net.ListenUDP("udp4", bindAddrFor(e.stunAddr))` + `stun.Lookup` → `[localEP, pubEP]` 去重。**STUN 失败不再直接 `backoff()`**:若此时有 v6 候选,则本轮丢弃 v4 族(关 socket、记日志)继续走 v6。
- **v6(新)**:`detectV6Egress() *net.UDPAddr` —— 向一个全局 v6 目标做一次 `DialUDP`(仅路由探测、不发包)取本机出口源地址;无路由 / 无 v6 栈则返回 nil。`net.ListenUDP("udp6", &net.UDPAddr{IP: egress.IP})` **绑定该出口**、广播 `socket.LocalAddr()` —— 源地址确定,`kcp` 严格源过滤能匹配回包。测试通过注入 `e.v6Addr = ::1` 提供 v6(真机不广播 loopback/ULA;`detectV6Egress` 已排除 unspecified/loopback/link-local)。
- `mine` 仍是单个 `[]candidate`(v4 在前,日志对齐)。
- `encodeCandidates`(direct.go:605)按 `c.Addr()` 的族写 `4`/`6`,分别 `As4()`/`As16()`;`decodeCandidates` 不动。

### 能力协商(v6 不使用,纯前瞻接缝)

- 新增 `ctrlCaps = 0x04`(direct.go:39-40 附近),载荷 sealed 的能力位域(本次 1 字节,未知位忽略)。
- **语义是「我理解该能力」,不是「我当前提供该能力」**:后者由候选列表表达(有 v6 候选 = 现在能用 v6)。二者不可混用。
- **可重复、幂等**:每次 punch 广播候选时一并重发 `ctrlCaps`,对端按位 OR。**不用「只发一次 + 已发标记」**——丢一帧即永久退化的语义与协商层相悖,重连/晚加入的 peer 都依赖重发;多一帧的成本不值得换不可恢复状态。
- **向后兼容已逐行核实**:`handleControl`(engine.go:461-494)是没有 `default` 的 switch,且 `OpenFrom` 在**每个 case 内部**——旧 host 收到 0x04 会静默落出,不报错、不碰 box、不改状态;帧格式 `[frameControl][kind][payload]` 本就任意 kind,无需改格式或版本号。
- **适用范围**:仅用于「对端不支持会导致尝试失败或破坏」的破坏性扩展。v6 候选旧 host 能安全忽略,不属此类。真正的例子是**候选族扩展**——`decodeCandidates` 遇未知族会丢弃**整个**列表(direct.go:646),那才是 caps 该管的事。
- 同一位域后续承载新能力,无需新增 kind(本次只放接缝,不承载其他能力)。

### 族选择与同轮回退(对称性论证)

顺序是**两个候选列表的纯函数**,两侧独立算、结果一致:

1. **v6 优先,当且仅当**:双方列表都含 v6 候选。
2. 否则 v4(双方列表都含 v4)。

谓词只用**可观测的量**(我方列表、收到的对端列表),不引入 caps 回执这类单侧推断,故两侧对同一对列表必然同判。对称性:两侧各自计算的是**同一对**谓词 `(我方有 v6, 对端有 v6)`,与既有 hairpin 规则同构(那份设计文档已确立「对同一对值做比较,两侧结果必然一致」,docs/2026-09-09:132)。非对称情形:(a) 仅一侧有 v6 → 两侧都选 v4;(b) 都有 v6 但单向不可达 → `seedHandshake` 两侧同窗口判败 → 都退 v4;(c) 我方 v6 绑失败 → 我方不广播 v6 → 两侧都选 v4。

**轮次一致性**:两侧 punch 由候选 request/response 驱动,不同钟,各自可能对**不同代**的列表求值;因谓词对称且失败即同轮换族,偏离会收敛(至多多付一次 seed),不作为阻塞项。若要严格消除,可在候选帧带递增 round id、只用同 id 列表求值——记为可选加固。

每族一次尝试:选目标 → `kcp.NewConn4(dc.conv(), u, nil, 0, 0, true, sock)` → `seedHandshake(kcpConn, seedTimeout)`。失败则关掉该 KCP 连接(`ownConn=true` 会连带关掉该族 socket)并立即跑下一族;两族都失败才 `backoff()`。轮内**不重新交换候选**,两侧用相同超时执行相同序列。

- **拨号规则**:v6 取对端列表里**第一个 v6 候选**(通配绑使「不需要双方选同一对」);v4 保持既有 hairpin 规则(direct.go:422-425)。
- **socket 所有权**:一轮最多两个 socket(v4/v6),`keep` 布尔升级为「胜者 socket 交给 `markUp`,败者显式关闭」。
- **已知时序影响**:一轮最长 2×`seedTimeout`,可能超过 `punchWaitTimeout`——该次 `OpenStream` 会先走 relay,但打洞 goroutine 仍会完成,后续 stream 走直连(与今日慢打洞行为一致)。代码注释写明两族用**相同**的 `seedTimeout`。

### 门控变更

新增 `Engine.directEnabled()`(=`e.direct && (e.stunAddr != "" || e.v6Addr != nil || e.v6Available)`),`maybeStartDirect`/`punchAndWait` 用它早返回。`--direct=false` 是强制 relay-only 的总开关;`--stun` 只管 IPv4 的 STUN 服务器,v6 独立于它。

## 任务分解(每步独立可验证)

1. **codec 族化** —— `encodeCandidates`(direct.go:605)按族写 4/6。测:v4+v6 混合列表 encode→decode 往返(含端口与顺序);legacy 纯 v4 帧仍可解;未知族仍报错。
2. **`detectV6Egress()`** —— 路由探测取出口地址(无全局 v6 返回 nil);`Engine.v6Available` 作门控、`v6Addr` 作显式覆盖(测试)、包级 `v6Egress` 作 seam,**每轮 punch 重新探测**(出口变化无需重启)。测:`v6Addrs` 过滤(排除 v4/v4-mapped);v4-mapped 归一化为 family 4;`--direct=false` 不打洞。
3. **能力协商接缝** —— `ctrlCaps` 常量 + sealed 能力位域 + 每次 punch 广播候选时幂等重发 + 每 peer 位域(OR 累积)+ `handleControl` 新增 case。测:按位 OR、重复帧幂等、丢帧后下一轮重发可恢复;**未知 kind / 未知位不改变任何状态**(模拟旧 host)。此步与 v6 广播**相互独立、不做门控**。
4. **punch 重构** —— `punch()`(direct.go:340-470)按上面「候选收集 / 族选择 / 同轮回退 / socket 所有权」改造;新增 `v6Addrs(cands)` 紧邻 `ipv4Addrs`(direct.go:523);门控改 direct.go:113/:125。测见下。
5. **文档** —— `main.go:54` 的 `--stun` 帮助文案(依风险 6 的 opt-out 决定落笔;"empty disables direct" 已不成立)、`p2p/CLAUDE.md`(标志表 + Direct data plane 段 + `--stun` 语义)、`README.md` 与 `README.zh-CN.md` 的标志表、以及 `docs/2026-09-09-p2p-mutual-punch-design.md` 补一节附录(其拨号目标规则与「对 engine.go 零改动」的断言在本计划后不再成立)。

## 测试策略

仓库没有 `t.Skip`/`testing.Short` 惯例。v6 测试自守卫:探针 `net.ListenUDP("udp6", ::1)` 失败则跳过。复用既有脚手架:`relayServer`(engine_test.go:155,TCP/WS,族无关,可直接用)、`startFakeSTUN`(direct_test.go:40,udp4-only,**本次不需要 udp6 版**——v6 候选不走 STUN)、`newEngine`、`startEcho`、`roundTrip`、`waitFor`、`hasDirect`。

| 测试 | 断言 |
|---|---|
| `TestDirectV6NoSTUN` | 注入 `localV6Addrs` 返回 `::1`,`stunAddr` 留空 → **首轮**即建立 v6 直连(无 caps 门控、无 backoff 等待) |
| `TestDirectV6FallbackToV4` | 注入黑洞 v6(`2001:db8::1`)+ 正常 fake STUN → 同轮 v6 失败后 v4 建立,`dc.peerAddr` 是 v4 |
| `TestDirectNoCandidateSourceRelayOnly` | 注入空 v6 + `stunAddr == ""` → `punchAttempts == 0`,relay 往返正常 |
| `TestV4OnlyPeerStillDirectV4` | 我方广播 v4+v6,对端只广播 v4 → 两侧都建立 v4 直连(v6 候选不破坏 v4,旧 host 兼容回归) |
| `TestCapsBitfieldIdempotent` | 部分/重复位域帧 → 按位 OR、幂等;未知位被忽略 |
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
4. 若 `punchWaitTimeout` 在两族尝试间到期,首次 `OpenStream` 走 relay,后续走直连。接受并写入注释。
5. ~~多宿主机 v6 源地址 ≠ 被拨候选~~ **已解决**:改为单一出口地址并绑定它,源 == 被拨候选。
6. ~~`--stun ""` 语义变化~~ **已解决**:新增 `--direct` 总开关(默认 true),`--stun` 仅影响 IPv4。

## 不做(YAGNI)

NAT66/前缀转换的 v6 STUN 探测、链路本地(zone)候选、多 v6 候选轮询、v6 候选的 PCP/UPnP 映射。caps 本次只落位域接缝,不承载其他能力。
