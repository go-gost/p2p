# p2p

[![Go Reference](https://pkg.go.dev/badge/github.com/go-gost/p2p.svg)](https://pkg.go.dev/github.com/go-gost/p2p)

[English](README.md) · **简体中文**

为 [GOST](https://github.com/go-gost/gost) 的 [p2p 插件](https://github.com/go-gost/plugin) 协议服务的 P2P 隧道宿主，既可以作为独立二进制运行，也可以作为 **Go 库嵌入到其他进程**（见[进程内嵌入](#进程内嵌入in-process)）。它让 GOST 通过本宿主打开的隧道，建立到链节点的网络通路——穿越策略（rendezvous、relay、打洞）完全由插件决定，GOST 侧永远只看到一条普通的字节流（`Tunnel` gRPC 流）来承载它的协议。

**当前状态：stub + mux + DERP relay + STUN/UDP 打洞 + 数据报通道。** 宿主用本地 TCP 转发桥接隧道：stub 模式（回环）直接转发，**DERP relay** 模式（engine）跨机/NAT。engine 模式下，relay 会话建立后，两端各自用 STUN 探测 NAT 并打 UDP 洞；直连路径（KCP + smux）建立后，新隧道走直连、relay 保持为回退。支持内层 dialer `tcp/tls/ws/mtcp/mtls/mws/udp`——mux 一族把一条隧道复用成多路会话，`udp` 则要求一条**数据报流**而不是字节流（tun 链路靠它：设备归 GOST 管，本进程只是管道）。

## 工作原理

```
GOST client ──OpenTunnel(peer, network)──▶ p2p host (gRPC, :8003)
GOST client ◀──{ok, id}────────────────────  p2p host
GOST client ══Tunnel 流（"id" metadata）══▶ p2p host ──bridge──▶ peer
```

- `peer` 不透明：语义由插件定义（DERP 模式下是 base64 公钥，stub 模式下是 `host:port`）。
- `OpenTunnel` 只做授权并返回一个密码学随机、单次使用的 `id`。**数据走绑定该 id 的 `Tunnel` gRPC 流**（经 `id` metadata 键）——没有本地 endpoint 可拨，因此 GOST 与本宿主之间的防火墙挡不住数据面。关闭流即关闭隧道；流的生命期就是隧道的生命期。
- GOST 侧接线（tunnel dialer、配置）在 `go-gost/x`（`x/p2p/`）；线上契约在 `go-gost/plugin`（`p2p/proto`）。

## 定位：一个通用的 P2P 连通性原语

`p2p` 是一个 **P2P 连通层，不是开箱即用的加密隧道**。它的契约刻意收得很窄：

> 给我一个 peer 公钥，我返回一条 TCP 隧道；NAT 穿越尽力而为（STUN + UDP 打洞，relay 回退）；端到端可达性归本层，安全性归调用方。

它提供的是**可达性，不是策略**——与 IP/TCP 同款分层：

- **加密在设计上不归本层管。** relay 与打洞链路都走明文（与 relay 的信任模型一致：它能看到但永远解不了密）。保密属于上一层——在隧道之上跑 `tls`/`mtls`/`wss`，正如 GOST 内层 dialer 所做。这是标准的分层，不是缺口。
- **peer 发现是增强项，不是必需项。** peer 以 base64 curve25519 公钥寻址——这是完整的寻址方案。name→key 查找刻意不做（见 Roadmap）。
- **relay 是 NAT 穿越的固有前提。** 跨 NAT 没有 rendezvous 就不可能可达；`derper` 是部署/基础设施选型，不是设计缺陷。对称 NAT 的对端会永久留在 relay 上。

**接入方需要自备：** 一个 relay（自建 `derper` 或第三方 DERP）、要连接的各 peer 公钥，以及（若需要保密）隧道之上的自有加密。

## 快速开始

```bash
go build -o p2p ./cmd/p2p
./p2p --addr 127.0.0.1:8003
```

| 参数 | 默认值 | 含义 |
|---|---|---|
| `-C` | *(空)* | 配置文件（YAML）；配置值作为默认，显式传入的 flag 覆盖 |
| `--addr` | `127.0.0.1:8003` | gRPC 控制面监听地址 |
| `--token` | *(空)* | 控制面认证 token；为空则不做校验 |
| `--derp` | *(空)* | DERP relay URL（`wss://host/derp`）；启用 engine 模式 |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 私钥文件（hex）；缺失则自动生成 |
| `--target` | *(空)* | 入站隧道桥接目标（可重复；裸 `"host:port"` 进 tcp 池，`"udp://host:port"` 进 udp 池；DERP 模式） |
| `--forward` | *(空)* | 预配置静态端口转发 `"listen-addr=peer-key"`（可重复；DERP 模式） |
| `--stun` | *(空)* | STUN 服务器（host:port），用于 IPv4 直连路径；IPv6 直连无需 STUN |
| `--direct` | `true` | 尝试直连（打洞）路径；`false` 强制仅走中继 |
| `--tls.secure` | `true` | 校验 relay 的 TLS 证书（`false` 信任任意证书） |
| `--tls.caFile` | *(空)* | 用于信任 relay 自签证书的 PEM CA 文件 |
| `--log.level` | `info` | 日志级别：`trace`、`debug`、`info`、`warn`、`error`、`fatal` |
| `--log.format` | `json` | 日志格式：`json` 或 `text` |
| `--log.output` | `stderr` | 日志输出：`stderr`、`stdout`、`none` 或文件路径（按 100MB 轮转） |

## 配置文件

所有 flag 都可以写进 YAML 配置文件（gost 风格 `-C`）：配置值作为默认，显式传入的 flag 覆盖；
`--forward` flag 与配置里的 `forwards` 列表叠加生效。

配置文件由 CLI（`cmd/p2p`）读取；库本身不带文件读取器，`addr`、`token`、`log` 是 CLI 自己的
键——`p2p.Config` 里没有这些字段（它们属于部署设置，不属于 endpoint）。

```bash
./p2p -C p2p.yaml
```

```yaml
addr: 127.0.0.1:8003
token: gost
derp: wss://derp.example.com/derp
key: peer.key
target: 127.0.0.1:18080
stun: stun.example.com:3478
tls:
  secure: false
  caFile: /etc/p2p/ca.pem
log:
  level: debug
  format: text
  output: /var/log/p2p.log
  rotation:
    maxSize: 50
    maxAge: 7
    maxBackups: 3
    localTime: true
    compress: true
forwards:
  - listen: 127.0.0.1:18080
    peer: <peerB-key>
```

让 GOST 链节点指向它：

```yaml
p2ps:
  - name: p2p-1
    plugin:
      type: grpc
      addr: 127.0.0.1:8003
      token: gost                       # 需与宿主的 --token 一致

chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: 192.168.1.10:8080   # stub 模式下桥接到的 "peer"
            connector:
              type: http              # connector 跟随 peer 的协议
            dialer:
              type: tcp
            metadata:
              p2p: p2p-1              # 该节点的基础路径走插件
```

## 进程内嵌入（in-process）

`p2p` 就是一个普通 Go 库——CLI 只是它之上的 flag/config 前端。应用可以把 endpoint 嵌进自己的
进程，而不必在旁边跑这个二进制：无子进程、无 loopback gRPC 控制面、无认证 token。数据面与 gRPC
transport 完全一致（两者跑同一个 `serveTunnel`，只是流的载体不同——内存管道），每条隧道都以
`net.Conn` 的形式交回给调用方。

库是四个包、单一依赖方向：
[`github.com/go-gost/p2p`](https://pkg.go.dev/github.com/go-gost/p2p)（契约——`Config`、
`Status`、sentinel error；只依赖标准库）、
[`…/p2p/endpoint`](https://pkg.go.dev/github.com/go-gost/p2p/endpoint)（endpoint：身份、relay
engine、forward、`Dial`/`Listen`）、
[`…/p2p/grpc`](https://pkg.go.dev/github.com/go-gost/p2p/grpc)（transport：把 endpoint 按插件协议
对外提供）、以及 `internal/host`（endpoint 背后的 engine，模块外不可导入）。身份处理、timing
参数与信任边界见[嵌入指南](docs/embedding.md)。

从 v0.4.x 升级：`p2p.New`/`p2p.Host` 变成 `endpoint.New`/`endpoint.Endpoint`，`Host.Tunnel()`
facade 已删除——`Dial`/`Listen` 直接在 endpoint 上。

```go
import (
	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/endpoint"
)

ep, err := endpoint.New(&p2p.Config{
	Derp:   "wss://derp.example.com/derp", // 留空 = stub 模式（peer 即普通 host:port）
	Key:    "peer.key",                    // curve25519 密钥文件；缺失时自动创建
	Target: "127.0.0.1:18080",             // 入站隧道桥接到此处（DERP 模式）
})
if err != nil {
	return err
}
defer ep.Close() // endpoint 拥有 engine、forward 与入站监听器

// Connect 启动 DERP engine 与配置的 forward。stub 模式无需调用。连接失败不致命：
// engine 会在后台重试；forward 注册失败会返回——那个是致命的。
_ = ep.Connect()
log.Printf("my public key: %s", ep.PublicKey()) // peer 用这个公钥寻址本 endpoint

// peer：DERP 模式下是 base64 公钥，stub 模式下是 host:port。
conn, err := ep.Dial(ctx, "tcp", peer)
if err != nil {
	return err
}
defer conn.Close() // conn 本身就是隧道——关闭它即拆除隧道
```

- **拿到什么。** `Dial` 返回一个 `net.Conn`：像 socket 一样读写，应用原本跑在 TCP 上
  的任何东西（自有协议、TLS、请求/响应循环）原样在其中穿行。`network` 决定流的语义——`udp`
  （含 `udp4`/`udp6`）返回保留数据报边界的 conn，其余为字节流。
- **生命周期。** `ctx` 只约束这次调用；隧道比它活得更久。返回的 conn 就是取消句柄——关闭它，隧道、
  它的 peer 拨号与记账一起消失。没有别的东西需要跟踪，也没有 close RPC。
- **入站。** DERP 模式下同一个 endpoint **也**接受 peer 发来的隧道：每条入站流在其存续期内桥接到
  配置的 `Target`/`Targets`。未配置 target 时，`Listen()` 把入站流交给嵌入方：一个
  `net.Listener`，其 Accept 出的 conn 以 peer 的 base64 公钥作为 `RemoteAddr()`，嵌入方据此按
  peer 路由并自持服务栈（统计、认证、录制）。两者互斥。
- **关闭。** `ep.Close()` 关停 endpoint：engine、forward、入站监听器与隧道记账（幂等）。挂在
  endpoint 上的 transport 随之结束；关闭 transport 只停它自己的监听器。
- **不需要控制面。** `Start`/`Serve` 绑定 gRPC 监听器，只有进程外客户端才需要；嵌入方调用
  `Connect`（stub 模式下什么都不用调），永不启动 server。
  [配置文件](#配置文件) 下的每个字段都是可在代码里直接设置的 `Config` 字段。

### 同进程提供插件协议

endpoint 是共享的：挂上 gRPC transport，就能在服务 GOST 插件客户端的同时让本进程内拨号——
一个身份、一条 relay 连接、每个 peer 一条 channel。

```go
import (
	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/endpoint"
	"github.com/go-gost/p2p/grpc"
)

ep, _ := endpoint.New(&p2p.Config{Derp: "wss://derp.example.com/derp", Key: "peer.key"})
srv, _ := grpc.New(ep, grpc.WithAddr("127.0.0.1:8003"), grpc.WithToken(token))
addr, err := srv.Start() // 绑定控制面并连接 endpoint

srv.Close() // 只停控制面；endpoint 继续运行
ep.Close()  // 拆除 endpoint（及其上的所有 transport）
```

endpoint 的形态是刻意结构化（structural）的——`Dial(ctx, network, peer)` + `Close()`——因此已经
定义了自己 tunnel-provider 接口的应用，可以让 `*endpoint.Endpoint` 直接满足它，而不必写适配器。

## DERP 模式（跨机）

DERP engine 通过 [DERP 服务器](https://tailscale.com/kb/1236) 中继隧道，使 NAT/防火墙后的 peer 能互相到达。relay 服务器是官方 `derper` 二进制；本宿主走它的 WebSocket 路径（`Upgrade: websocket` + 子协议 `derp`），这也使它可部署在 Cloudflare 等支持 WebSocket 的代理之后。**注意：** 这条 WebSocket 路径是 Tailscale 自己的浏览器端传输（`cmd/tsconnect/wasm`，经 `derpserver.AddWebSocketSupport`）——它**没有**被 [自定义 DERP 服务器](https://tailscale.com/docs/reference/derp-servers/custom-derp-servers) 文档覆盖（那文档只讲原生 `Upgrade: DERP` hijack），所以把它当作事实标准而非文档化 API。

```bash
# relay 服务器（自建；首次运行自动生成密钥配置）
derper -c /etc/derper/derper.json -hostname derp.example.com -certmode manual -certdir /etc/derper/certs -a :443

# peer 侧——在 relay 注册，把入站隧道桥接到本地 GOST
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080

# client 侧——照常提供 GOST 控制面
./p2p --derp wss://derp.example.com/derp --key client.key --addr 127.0.0.1:8003
```

每个宿主首次运行会生成一对 curve25519 密钥，并在启动时打印它的**公钥**（base64）。DERP 模式下，GOST 链节点的 `addr` 是 *peer 宿主的公钥*，而不是 `host:port`。GOST 侧其余配置不变。

### DERP 帧格式

relay 链路是一条承载 DERP 二进制帧的 WebSocket。值得了解的有两层：DERP 协议本身（与所有 Tailscale 客户端共用），以及本宿主放进被中继包**内部**的一层很小的 p2p 分帧。

**DERP 帧** —— `[type 1B][length 4B 大端][body]`，取自 `tailscale.com/derp@v1.102.3`：

| Type | 名称 | Body |
|---|---|---|
| `0x01` | ServerKey | 8 字节 magic（`DERP` + 钥匙 emoji）+ 32 字节服务器公钥 |
| `0x02` | ClientInfo | 32 字节客户端公钥 + 24 字节 nonce + 用服务器公钥的 NaCl-box（JSON `{Version, CanAckPings}`） |
| `0x03` | ServerInfo | 24 字节 nonce + NaCl-box（JSON）；token-bucket 提示，仅供参考 |
| `0x04` | SendPacket | 32 字节目标公钥 + 包体（≤ 64 KiB） |
| `0x05` | RecvPacket | v2：32 字节**来源**公钥 + 包体 |
| `0x06` | KeepAlive | 无 —— no-op |
| `0x08` | PeerGone | 32 字节公钥 + 1 字节原因（信息性） |
| `0x09` | PeerPresent | 32 字节公钥（信息性；derper 只发给 mesh watcher） |
| `0x12` / `0x13` | Ping / Pong | 8 字节载荷；`Recv` 收到 Ping 会回一个 Pong |

握手：服务器先发 `ServerKey`，客户端回 `ClientInfo`（用服务器公钥 box，以证明持有私钥），服务器再回 `ServerInfo`。其余全部是 `SendPacket`/`RecvPacket`。**未知帧类型直接跳过**（参考客户端的 `recv` switch 没有 default 分支）——同样的前向兼容规则。客户端只靠 32 字节公钥寻址；base64 形式就是该公钥。

**p2p 分帧** —— 每个 `SendPacket`/`RecvPacket` 内部的字节以一个类型字节开头：

| 字节 | 含义 |
|---|---|
| `0x00` | 控制帧：`[0x00][kind 1B][NaCl-box 载荷]` |
| `0x01` | 数据帧：`[0x01][smux 字节流]` —— 每次 smux 写对应一个 DERP 包 |

控制 kind：`0x02` 打洞候选（sealed `[count]([family][addr][port])*`）、`0x03` udp 隧道拨号通知（sealed，空）、`0x04` 能力位域（sealed 1 字节；bit 0 = 支持 IPv6，随每次广播重发、接收方 OR）。所有控制载荷都用对端公钥 seal（`PrivateKey.SealTo`），relay 只能路由、无法伪造。控制帧由 engine 消费；数据帧喂给每个 peer 的 smux 会话。

### 打洞

两端都在 engine 模式时，relay 只用于建立首条会话并承载控制面。后台每个 peer 向 derper 内建 STUN 服务器（默认端口 `3478`，`-stun` 默认开启）查询自己的公网 UDP endpoint，经 relay 与对端交换，并在同一 UDP socket 上建立 **KCP** 会话。

打洞是**对称**的：双方各自以同一确定性 KCP conv 向对端候选拨号（互撞同时打开），且只有**双方都完成 echo 握手**（各自看到自己的 token 完整往返）后会话才可用——半通路径永远不会产生「假直连」。这消除了旧版「一边 dial、一边 accept」的不对称——当只有一个方向能打通时会失败（典型：k3s pod 内的 peer，其入站 UDP 需要 pod 先发出过包）。

成功后，新隧道在直连 smux 会话（KCP + smux）上开流；relay 会话保持，直连失败时静默回退 relay 并重新打洞。直连路径即使 relay 掉线也继续工作——只有 *新的* 打洞才需要 relay 回来。设置 `--stun` 时，预配置的 `--forward` 会在启动时预热其 peer 的直连路径，首个连接无需等待打洞。直连默认开启（`--direct=false` 强制仅走中继）。IPv6 是一等候选族：有全局 IPv6 出口的宿主会绑定并广播该地址（无需 STUN、无 NAT）；当两端都提供 IPv6 时优先走 IPv6，若该路径未打通则在同一轮内回退 IPv4。

时间参数仅经配置文件调整（不加 flag）；未设即用默认，非法值启动即报错：

```yaml
timeouts:
  punchWait: 5s       # 流等待直连的上限，超时回落 relay
  punch: 10s          # 打洞全程窗口（候选等待 + 拨号/seed）
  seed: 5s            # 对称 echo 握手窗口
  backoff: 30s        # 打洞失败后的重试间隔
  derpKeepAlive: 30s  # DERP 保活（须低于代理空闲超时）
  smux:
    interval: 10s
    timeout: 30s      # 必须 >= 2x interval
```

对称 NAT 打洞失败；这类 peer 永久留在 relay（周期性重试）。KCP 传输不加密，与 relay 的信任模型一致——保密是内层 dialer 的职责（`mtls`/`tls`/`wss`）。

derper 的 STUN 服务器只应答 Tailscale 的 binding-request 方言（`SOFTWARE` + `FINGERPRINT` 属性），并绑定与 `-a` 相同的 IP。用显式 IP 运行 derper（`-a 1.2.3.4:443`），使 STUN 在对端要查询的地址族上可达；用通配 `-a :443` 时它会绑到 IPv6-only，默认的 IPv4 `--stun`（`derp host :3478`）够不着——此时需显式设置 `--stun`。

## 数据报通道（tun 链路，Linux）

链节点把 dialer 设为 `udp` 时，请求的是一条**数据报流**（`network=udp`）而非字节流。它和其他隧道一样由 `Tunnel` 流承载：在本宿主内，每端把持久的 per-peer 边（通往对端的直连或 relay 流）与最新一条 GOST 隧道的流配对，在两边之间泵字节。GOST 侧 conn 把每个数据报成帧（2 字节长度前缀），对端 GOST 侧 conn 解帧——包边界因此穿过字节流数据面，而**本宿主完全不解析数据**。tun-to-tun 链路正是靠它——**设备由 GOST 拥有**（`tun` listener 创建并配置设备，`tun` handler 桥接），本宿主只是管道。tun 是独占打开的，设备无法共用，让 GOST 用自己的 tun 栈才是重点。

```bash
# 两端都一样：没有 --target，也不碰设备。对端公钥写进 GOST 的节点 addr。
./p2p --derp wss://derp.example.com/derp --key a.key --addr 127.0.0.1:8003 --stun derp.example.com:3478
```

```yaml
# GOST 侧（两端各一份；见 gost 仓库的 play/p2p-tun.yaml）
p2ps:
  - name: p2p-1
    plugin: {type: grpc, addr: 127.0.0.1:8003}
services:
  - name: tun-0
    addr: :0                      # tun listener 不绑任何 socket
    handler: {type: tun, chain: chain-0}      # 有 chain 无 forwarder = 客户端模式
    listener:
      type: tun
      metadata: {name: p2p0, net: 10.10.0.1/30, mtu: 1420}   # 对端为 10.10.0.2/30
chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: <peerB-key>     # p2p 模式下 addr 就是 peer 公钥
            dialer: {type: udp}   # 数据报语义
            connector: {type: forward}   # 透传（默认 connector 是 http）
            metadata: {p2p: p2p-1}
```

每个 peer 一条通道，被到它的所有隧道共享并做引用计数：GOST 每次拨号开一条隧道、重连时关闭，因此最后一条关闭时通道被拆除、下次 Open 时重建。只有**公钥较小**的一端打开 peer 边的流，另一端由常规 accept 路径服务。重拨会接管本地边（后拨者胜），而 peer 边在其断线期间以退避重连，本地边持续存活。链路优先走直连（打洞）路径，失败回退 relay，与隧道一致。`network=udp` 需要 engine 模式（`--derp`）：通道以 peer 公钥寻址。

任一侧暂时没有活边时字节直接丢弃（IP 能容忍丢包），因此暂时无话可说的一端依然可达。数据面**不加密**，与其余数据面一致：这里没有内层 dialer 可托付，仅在可信链路上使用，或在链路之上自行加密。

## UDP target(全局数据报出口)

`udp://` 的 `--target` 是一个**全局数据报出口**——它是数据报通道的第二种*端*，与上面的 per-peer 通道不同，**不绑定任何 peer**。每条入站的带 `P2PU` 标记的数据报流都从 udp 池里取一个 target、拨它，并在该流的生命期内与它桥接：流上的帧在出口变成裸 IP 数据报，每个数据报又成帧回写到流上。出口侧**零 per-peer 状态**——没有预建通道、没有 per-key socket，没有任何东西活得比一条流更久。这正是 NAT 后的 `tun` *server* 想要的形态：多个 NAT 后的 `tun` client 访问一个 NAT 后、持有单块 tun 设备的 peer。

```bash
# 出口侧：p2p 带一个指向 tun server 的 udp target —— 无 --allow、无 per-peer 配置
./p2p --derp wss://derp.example.com/derp --key outlet.key \
      --target udp://127.0.0.1:8421 --stun derp.example.com:3478

# 出口侧：GOST tun SERVER —— 不要设 tun.p2p（那个旗标是单 peer 模式）
#   gost -L "tun://127.0.0.1:8421?net=10.10.0.1/24&keepalive=true&ttl=10s&token=<passphrase>"
#   auther：user = 各 spoke 的 tun IP，password = 共享 passphrase
#   sysctl -w net.ipv4.ip_forward=1     # 要访问出口身后的网络时
```

spoke 就是原样的 `tun` client：`net 10.10.0.<n>/24`、`keepalive: true`、同一个 `token`、指向出口身后网络的 `route`；链节点 addr 填 **出口宿主公钥**，`dialer: udp` / `connector: forward`，与点对点链路完全一致。

- **两个端，一个 rendezvous。** 数据报通道配对的是两个*端*，p2p 不为任何一端特化。端 (1) 是本机的一条 GOST udp `Tunnel` 流——即上面的 per-peer `channel`，tun-to-tun 链路与 spoke 拨向出口都用这个通用 rendezvous。端 (2) 是 udp 的 `--target`——即这里的全局出口。一台宿主持哪一端是部署形态，不是模式。开流方由公钥序决定（公钥较小者开）：channel 侧经自己的 loop 开；出口侧没有 channel，靠对端带内的 udp dial 通知触发；持 channel 的一侧不会再跑那条 loop。
- **准入在调用方，不在 p2p。** 谁可用该出口由本层之上决定：tun `auther` 的 per-spoke passphrase、relay 的 `-verify-clients=true`，或简单的端口绑定/防火墙。**未认证的 `udp://` 出口等价于在数据面上直接暴露一个未认证的 tun server**——请在它前面放上 tun handler 的 `token`/passphrase（或等价物）。
- **`keepalive` 是 tun app 的职责，在 p2p 之上。** 出口侧源端口随 peer 边（重）建立而变，因此 tun server 按 spoke IP 建的路由要靠 tun client 的下一次 keepalive 刷新——这是 tun 应用的义务，不是 p2p 的契约。从不发 keepalive 的 tun client，在其第一次重连后，server 的下行就会指向一个死端口。在 spoke 上设 `keepalive`（其对端是 tun server，会回显并注册路由）；server 侧的 `keepalive/ttl` 也会让离场 spoke 的路由过期，而不是向死地址黑洞发送。

`--target` 可重复，分成两个池：裸 `host:port` 是 **tcp** 目标（入站字节流隧道），`udp://host:port` 是 **udp** 目标（上面的出口）。多个 udp target 会把入站数据报流轮询分摊到多个出口。

## Transport 统计

宿主通过既有的 gRPC `Status` RPC 暴露直连/中继统计，用来判断打洞在你自己的
peer 群体里到底有没有生效：

```bash
grpcurl -plaintext 127.0.0.1:8003 proto.P2P/Status
```

```json
{
  "tunnels": 4,
  "directPeers": 12, "derpPeers": 3,
  "punchAttempts": 45, "punchSuccess": 15,
  "streamsDirect": 210, "streamsDerp": 30
}
```

`directPeers`/`derpPeers` 是 gauge——每个 peer **当前**实际走哪条路；`punch*`
与 `streams*` 是自启动以来的累计值。`punchAttempts` 一直涨而 `punchSuccess`
不动，说明打洞在被尝试但失败（对称 NAT / CGNAT）——正是 IPv6 或端口映射要解决
的场景。设了 `--token` 时加 `-H 'token: <token>'`。

## 安全

控制面默认**未认证**：任何能访问 `--addr` 的进程都能让本宿主拨任意地址。让 `--addr` 保持回环（默认值）。跨机部署需设 `--token`（GOST client 以 gRPC metadata 发送）**且**配控制面 TLS——仅凭 token 目前走的是明文 gRPC 通道。

`-verify-clients=false` 的 DERP relay 是开放中继：它能看到并丢弃字节，但永远不解密。保密是内层协议的职责（用 `mtls`/`tls`/`wss` 内层 dialer）；relay 是传输，不是信任。

**数据报通道**同样是明文：IP 包经 relay 或打洞路径不加密传输，而且与隧道不同，本宿主里没有东西给它加密（GOST 的 `tls`/`mtls` dialer 对 `udp` 隧道不适用）。仅在可信链路上使用，或在链路之上自行加密。

**udp 出口**把准入交给调用方：p2p 不做准入。谁可访问出口的 tun server 由上层决定——tun `auther` 的 per-spoke passphrase、relay 的 `-verify-clients=true`，或端口绑定/防火墙。前面没有东西挡着的出口，就是一个暴露在数据面上的未认证 tun server。

## Roadmap

1. ~~STUN + UDP 打洞隧道~~——已交付（KCP + smux 直连，DERP relay 回退）。
2. rendezvous 地址发现——已放弃：derper v1.102.3 只向 mesh watcher 发送 `PeerPresent`，从不发给开放中继客户端，因此基于 presence 的名字发现不可行。peer 以 base64 公钥寻址；人类可读名字应放在 GOST 配置里，而非 p2p 侧的注册表。
3. 数据报通道（tun/tap 走隧道）——已交付（`network=udp`）：每 peer 一条字节管道，把对端流与最新一条 GOST 隧道的流对接，全部在彼此的 `Tunnel` 流内承载。设备本身归 GOST（`tun` listener/handler），本宿主只是管道。
4. UDP target 出口——已交付：`udp://` target 是一个全局数据报出口（流级、零 per-peer 状态），于是多个 NAT 后的 spoke 能访问一个 NAT 后、持有单块 `tun` 设备的 peer（server 的 per-IP 路由表是 GOST 的）。准入在调用方。

## License

MIT
