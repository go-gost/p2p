# 阶段三 M1:服务名发现 —— DERP 广播公告 + 宿主内 name→key 解析

> **验收结论(2026-09-06):不通过,方案作废,已回退。**
> 真 derper v1.102.3 实测与方案前提矛盾:**PeerPresent/PeerGone 只发给 mesh watcher(需 `-mesh-psk-file` 的 `canMesh` 权限),不发给 `-verify-clients=false` 开放中继的普通客户端**(源码 `derpserver.go:816 broadcastPeerStateChangeLocked` 只遍历 `s.watchers`;`:980 addWatcher` 对 `!canMesh` 直接失败;`:1576 canMesh = meshKey 相等)。因此 `online` 集恒空 → 事件驱动公告永不触发 → 名字发现整体失效;engine_test 的 fake relay 自造了"注册即广播 presence"这一真实 derper 没有的行为,单元测试全绿是假阳性。附带:即便收到 presence,v1.102.3 是 51B/key(key+IPv6+port+flags),derpclient 按 32B 切片解析也错。
> **决策**:砍掉 name→key 发现,保持 derp 里程碑的按 base64(key) 拨号(key 即地址、稳定、无注册表、无碰撞)。discovery 改动已 `git revert e28becd`(提交 03eed32),p2p 回到按 key 形态。若未来要名字,用 GOST 配置层静态映射 name→key(hosts/resolver),不动 p2p。

## Context

DERP 中继里程碑([[2026-09-06-p2p-derp-relay]])打通跨机隧道,但 peer 寻址是**离线交换的公钥**(key 即地址,已锁定)。M1 实现阶段三的**地址发现**小块:让服务端宿主声明服务名、客户端按名发现,摆脱每次换 key。范围决策(2026-09-06 与用户敲定):

- 服务名发现先行;STUN+UDP 打洞(M2)只留协议位、不动手;
- **名字解析放宿主内**:`OpenTunnel(peer)` 收到非 32B key 时按服务名查宿主缓存得 key,再走原流程。proto 不动、x/ 零 diff,与 derp 里程碑同风格;
- 客户端从 `-F p2p://<base64公钥>` 变为 `-F p2p://<服务名>`(peer 保持 opaque)。

## DERP 快速回顾(与 README/CLAUDE 对齐)

DERP 是**包中继**:所有 peer 永连 derper,以 32B 公钥=地址互相发包,derper 只按键路由(未知目标静默丢弃、不回环)。传输走 WebSocket-DERP(RFC6455 subprotocol `derp`,官方 derper 无条件挂 `AddWebSocketSupport`),成帧在 WS 字节流之上:`[type 1B][len 4B BE][payload]`。握手 3 帧:ServerKey(magic+服务端公钥)→ ClientInfo(客户端公钥+box JSON 自证)→ ServerInfo(box JSON)。稳态:SendPacket(`{dst,bytes}`)→ derper → RecvPacket(`{src,bytes}`);KeepAlive/Ping/Pong 保活;**PeerPresent/PeerGone 广播在线状态**(当前 `Recv` 当 no-op 丢弃)。与 GOST relay/tunnel 协议的关系:同"双向外连公共中继 + 预共享身份当地址"的内网穿透套路,但 DERP 在包中继层(流需上层 smux 搭)、relay 在连接/会话层(自带 mux);DERP 原生存在性广播(PeerPresent)是 relay 所没有的结构优势——M1 正是用好这一优势。

## 关键事实(已验证)

- **跨 derper 的每对 key 之间只有一条 DERP 包流**(derper 以 key 寻址/路由)。smux 会话字节流与发现消息**物理上共用一个包流**——复用是传输事实,发现(控制面)与 smux(数据面上层)无逻辑依赖。
- **分流必须靠我们自己这一层显式打成帧,不能按负载内容判断。** p2p 引擎在 DERP 包流之上、会话层之下定义应用层帧 `[type 1B][payload]`,结构分类,不依赖任何会话协议的内部格式。
- smux 打包在 peerConn(视为 `net.Conn`)上,接受任意字节流、不感知分帧;发侧预置 type、收侧剥离,smux 始终看到干净字节流(`mux.go:64` Version=1、`session.go:413` 接收端校验)。
- derper 完成 `clientInfo` 注册后,向所有已注册客户端广播:连上者 `PeerPresent`(payload 32B 倍数)/ 断开者 `PeerGone`(32B+)。`derpclient.Recv` 现按 no-op 丢弃(`derpclient.go:301`)。
- DERp `RecvPacket` 帧自带 src key → **公告包只需 `kind+name`,主机身份由 src 提供**,不必重复携带公钥。
- derper 对离线 key 发包静默丢弃 → 公告发给"过期在线集"无害。
- GOST 侧:`x/p2p/tunnel_dialer.go:72` `tunnelBaseDialer{peer: addr}` 把 node addr 原样当 peer 传 `OpenTunnel` → `-F p2p://name` 的名字直达宿主,解析后返回 key 即可,GOST 零改。

## 设计

### 应用层帧:显式类型,结构分流(engine 内部,DERP 包级)

```
[type 1B][payload]
type 0x00 = 控制帧: [0x00][kind 1B][…]
    kind 0x01 = name-announce, payload = name 字节(≤64, ^[a-z0-9][a-z0-9-]{0,63}$;sanity 上限,非防碰撞约束——见边界)
    kind 0x02 = 预留(未来 M2 地址候选)  ← 只留位,不实现
type 0x01 = 会话数据块: payload 为 smux 会话字节流的切片
```

pump 分流只看 type 字节(我们自己发布的协议头):`0x00` → `handleControl(src, body)`,不进会话;`0x01` → 剥 type 入会话队列;未知 type 静默丢弃(前向兼容,同 derp 未知帧策略)。**发侧** `peerConn.Write` 给每块会话数据预置 `0x01`、控制帧预置 `0x00`;**收侧只剥一次**:pump 分流时剥 type、`body[1:]` 入队列,`peerConn.Read` 的 remainder 逻辑原样不动(双剥会坏 smux 流)。对 smux 的唯一要求是"接受字节流",不依赖其帧格式;未来 M2 换 QUIC 直连会话,type 0x01 语义不变。

### 存在性/拓扑:surface PeerPresent/PeerGone

- `derpclient`:新增 `type PresenceEvent struct{ Key PublicKey; Present bool }`、`Client.Presence() <-chan PresenceEvent`。`Recv` 遇 `framePeerPresent`(按 32B 切片迭代)/`framePeerGone` → 非阻塞入队(chan 满丢帧,存在性由公告周期收敛);不改变包返回路径(pump 单读者不变)。
- engine presence goroutine **按连接实例**(生命周期见 T2):present=true → 记入 `online` 集 → **对该新 key 触发即时公告**(低延迟发现);gone → 移除该 key 并清除它名下的服务条目。

### 公告与缓存

- 宿主以 `--service <name>`(可重复)声明服务名;未配置则不公告(纯拨号方)。
- engine 每 tick(`announcePeriod` 常量 15s)+ 新 peer present 时,对 `online` 集内每个 key 发当前全部服务名公告。
- 缓存 `svc map[string]svcEnt{key, lastSeen}`:**每名一条、最新者胜**(不做负载均衡);PeerGone 即清,TTL 60s(≈4 tick)兜底静默消失的 peer。
- 名称仅便利、非身份:open-relay 下任何人可向中继宣告任意名;真实门槛仍是内层协议(mtls/tls/wss)鉴权。

### OpenTunnel 解析(server.go)

derp 模式:peer 先 `parsePeerKey`;失败且 `engine.Lookup(name)` 命中 → 以解析所得 base64 key 走原流程;两者皆败 → `status.Errorf(codes.NotFound, ...)`(key 解析失败与未知名统一 NotFound,语义折叠是刻意的)。`t.peer`/`t.target` 存解析后的 key。

## 改动清单(全部在 `p2p/` 模块,与 derp 里程碑一致)

### T1 `p2p/internal/derpclient/derpclient.go`
- `PresenceEvent` 类型 + `Client.Presence() <-chan PresenceEvent`(懒建 buffered chan,**逐 client 私有;`Close()` 时关闭 → 消费 goroutine 随 range 退出**)。
- `Recv`:`framePeerPresent`(iterate 32B 切片)/`framePeerGone`(单 key,跳过 1B reason)分支从 no-op 改为非阻塞入队。

### T2 `p2p/engine.go`
- 字段:`services []string`、`online map[PublicKey]time.Time`、`svc map[string]svcEnt`、`announcePeriod`(构造成员,测试可缩短)。
- `ensureClientLocked`:为新 client 各起 presence goroutine + announce ticker——**presence 订阅绑定该 client 的 channel**(client 断开/`Close()` 关 channel 即退,和 pump/keepalive 一样随连接消亡;重连由每次 ensureClientLocked 重启订阅,否则旧 goroutine 在旧 channel 上空转泄漏);announce 在 `e.mu` 内先拷出 `online` key 列表、锁外再 `SendPacket`。
- `teardown`:`e.client = nil` 时同步清空 `online`/`svc`(连接没了,旧在线集/名字全是脏数据)。
- `Connect()` 后"立即发一轮"实为 no-op(此刻 online 为空)——公告由"新 key present → 即时公告"事件驱动覆盖,保留仅作保险。
- `pump()`:Recv 后先看 `body[0]`:`0x00` → `handleControl` 跳过会话路由;**`0x01` → 剥 type、`body[1:]` 入队列**(剥一次,Read 不再剥);未知丢弃。`peerConn.Write` 预置 `0x01`。
- 新增 `Lookup(name) (PublicKey, bool)`(TTL 内有效;读 `svc`,与 presence goroutine 写共用 `e.mu`)、`Announce(key)`(发当前服务集,presence/ticker 复用)。

### T3 `p2p/server.go`
- derp 模式 `OpenTunnel`:非 32B peer → `engine.Lookup` → 命中换 key / 失败 `codes.NotFound`。

### T4 `p2p/main.go`
- `--service <name>` 可重复 flag;校验名称;入 engine;启动日志打印 `announcing <name>`。

### T5 测试 + 文档
- `engine_test.go` 的 `relayServer` 扩展:ClientInfo 注册后广播 PeerPresent/PeerGone(真 DERP 线格式,模拟真实 derper)。
- 新测试:presence surface;A `OpenTunnel("name")` 打通 B echo;未知名 → NotFound;PeerGone 驱逐 → Lookup 失败;公告与既有 smux 会话包交错。全部 -race。
- 文档:本文件 + p2p/CLAUDE.md + README。

## 已知边界(记录,不修)

- 发现延迟 ≤ announcePeriod(事件驱动后新 peer 亚秒可见);无 query/response 拉取。
- 每名单条(newest wins);多 host 同名互相覆盖,PeerGone 后次级可在一 tick 内浮现(等效最终失败转移)。
- 名称全局平铺、无鉴权(open-relay 信任面,与公钥模型一致)。
- **"碰撞"只存在于 `OpenTunnel(peer)` 文本串(控制面),帧层/线路无此问题**:peer 字段被 base64 公钥与名字共用,判定树 = peer base64 解码恰 32B → 当 KEY;否则 → 当 NAME。线路/帧层是纯二进制(公告帧只带名字裸字节,身份由 derp src 的 32B key 提供),无 base64、无歧义。唯一边角:恰好 43 字符(32B 公钥 base64 的恒定长度)且解码恰 32B 的名字会被当 key、名字路径不可达——这是定义的优先级,不是二义,也只有用户自选 43+ 字符 base64 形名字才踩中。名字 ≤64 上限仅为公告帧/内存界,与碰撞无关。
- 公告包每帧单名:多服务名(×M)× 在线 peer(×N)= M×N 包/tick;规模小,接收端每帧单名最简单。
- 会话路径加 type 字节 = **线路格式变更**:两端须同版本引擎(宿主是新产物、无存量,可接受)。
- 多 key 轮询/负载均衡、名称即时 JSON 状态 API(proto 不动)均不做。
- M2(STUN+打洞+地址候选)另立 plan,type 0x00 内 kind 0x02 已验证留位。

## 验证

```bash
cd p2p && go build ./... && go vet ./... && GOWORK=off go build ./...
cd p2p && CGO_ENABLED=1 go test -race -count=1 ./...   # 新增用例 + 8/8 既有全绿
# e2e(真 derper): B: --derp wss://… --service foo --target <echo>;A 宿主 + GOST -F p2p://foo 打通;
#   neg:B 下线 → A OpenTunnel("foo") NotFound;  回归:桩/DERP 既有晋升用例
cd x && go build ./... && git status --short            # x/ 零 diff 核验
```