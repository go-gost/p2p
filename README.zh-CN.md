# p2p

[English](README.md) · **简体中文**

为 [GOST](https://github.com/go-gost/gost) 的 [p2p 插件](https://github.com/go-gost/plugin) 协议服务的隧道宿主进程。它让 GOST 通过本进程打开的隧道，建立到链节点的网络通路——穿越策略（rendezvous、relay、打洞）完全由插件决定，GOST 侧永远只看到一条本地可拨号的普通 endpoint。

**当前状态：stub + mux + DERP relay + STUN/UDP 打洞 + 数据报通道。** 宿主用本地 TCP 转发桥接隧道：stub 模式（回环）直接转发，**DERP relay** 模式（engine）跨机/NAT。engine 模式下，relay 会话建立后，两端各自用 STUN 探测 NAT 并打 UDP 洞；直连路径（KCP + smux）建立后，新隧道走直连、relay 保持为回退。支持内层 dialer `tcp/tls/ws/mtcp/mtls/mws/udp`——mux 一族把一条隧道复用成多路会话，`udp` 则要求一个**数据报 endpoint** 而不是字节流（tun 链路靠它：设备归 GOST 管，本进程只是管道）。

## 工作原理

```
GOST client ──OpenTunnel(peer)──▶ p2p host (gRPC, :8003)
GOST client ◀─{id, endpoint}─────  p2p host
GOST client ──dial endpoint─────▶ p2p host ──bridge──▶ peer (host:port)
```

- `peer` 不透明：语义由插件定义（DERP 模式下是 base64 公钥，stub 模式下是 `host:port`）。
- `endpoint` 不透明：v1 是一个本地可拨号的 TCP `host:port`。GOST 侧关闭连接即关闭隧道。
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
go build -o p2p .
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1
```

| 参数 | 默认值 | 含义 |
|---|---|---|
| `-C` | *(空)* | 配置文件（YAML）；配置值作为默认，显式传入的 flag 覆盖 |
| `--addr` | `127.0.0.1:8003` | gRPC 控制面监听地址 |
| `--bind` | `127.0.0.1` | 数据面监听 IP（每条隧道一个临时端口） |
| `--token` | *(空)* | 控制面认证 token；为空则不做校验 |
| `--derp` | *(空)* | DERP relay URL（`wss://host/derp`）；启用 engine 模式 |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 私钥文件（hex）；缺失则自动生成 |
| `--target` | *(空)* | DERP 模式下入站隧道的本地桥接目标 |
| `--forward` | *(空)* | 预配置静态端口转发 `"listen-addr=peer-key"`（可重复；DERP 模式） |
| `--stun` | *(空)* | STUN 服务器（host:port），用于直连打洞；留空则禁用直连（仅走中继）— 需显式开启 |
| `--tls.secure` | `true` | 校验 relay 的 TLS 证书（`false` 信任任意证书） |
| `--tls.caFile` | *(空)* | 用于信任 relay 自签证书的 PEM CA 文件 |
| `--log.level` | `info` | 日志级别：`trace`、`debug`、`info`、`warn`、`error`、`fatal` |
| `--log.format` | `json` | 日志格式：`json` 或 `text` |
| `--log.output` | `stderr` | 日志输出：`stderr`、`stdout`、`none` 或文件路径（按 100MB 轮转） |

## 配置文件

所有 flag 都可以写进 YAML 配置文件（gost 风格 `-C`）：配置值作为默认，显式传入的 flag 覆盖；
`--forward` flag 与配置里的 `forwards` 列表叠加生效。

```bash
./p2p -C p2p.yaml
```

```yaml
addr: 127.0.0.1:8003
bind: 127.0.0.1
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

### 打洞

两端都在 engine 模式时，relay 只用于建立首条会话并承载控制面。后台每个 peer 向 derper 内建 STUN 服务器（默认端口 `3478`，`-stun` 默认开启）查询自己的公网 UDP endpoint，经 relay 与对端交换，并在同一 UDP socket 上建立 **KCP** 会话。

打洞是**对称**的：双方各自以同一确定性 KCP conv 向对端候选拨号（互撞同时打开），且只有**双方都完成 echo 握手**（各自看到自己的 token 完整往返）后会话才可用——半通路径永远不会产生「假直连」。这消除了旧版「一边 dial、一边 accept」的不对称——当只有一个方向能打通时会失败（典型：k3s pod 内的 peer，其入站 UDP 需要 pod 先发出过包）。

成功后，新隧道在直连 smux 会话（KCP + smux）上开流；relay 会话保持，直连失败时静默回退 relay 并重新打洞。直连路径即使 relay 掉线也继续工作——只有 *新的* 打洞才需要 relay 回来。设置 `--stun` 时，预配置的 `--forward` 会在启动时预热其 peer 的直连路径，首个连接无需等待打洞。

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

链节点把 dialer 设为 `udp` 时，本宿主返回的不是字节流而是一个**数据报 endpoint**：一个本地 UDP socket，其每个数据报按 2 字节长度前缀成帧、一报一帧地送到对端的流上，从而在字节流数据面上保住包边界。tun-to-tun 链路正是靠它——**设备由 GOST 拥有**（`tun` listener 创建并配置设备，`tun` handler 桥接），本宿主只是管道。tun 是独占打开的，设备无法共用，让 GOST 用自己的 tun 栈才是重点。

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

每个 peer 一条通道，被到它的所有隧道共享并做引用计数：GOST 每次拨号开一条隧道、重连时关闭，因此最后一条关闭时 endpoint 被拆除、下次 Open 时重建。只有**公钥较小**的一端打开流，另一端由常规 accept 路径服务。链路优先走直连（打洞）路径，失败回退 relay，与隧道一致。`network=udp` 需要 engine 模式（`--derp`）：通道以 peer 公钥寻址。

endpoint 从收到的报文里学习 client 地址——GOST 在拨号后立刻发一个空数据报自报家门——重拨（新源端口）会接管，因此暂时无话可说的一端依然可达。流断开期间读到的数据报直接丢弃（IP 能容忍丢包）。数据面**不加密**，与其余数据面一致：这里没有内层 dialer 可托付，仅在可信链路上使用，或在链路之上自行加密。

## 安全

控制面默认**未认证**：任何能访问 `--addr` 的进程都能让本宿主拨任意地址。让 `--addr` 保持回环（默认值）。跨机部署需设 `--token`（GOST client 以 gRPC metadata 发送）**且**配控制面 TLS——仅凭 token 目前走的是明文 gRPC 通道。

`-verify-clients=false` 的 DERP relay 是开放中继：它能看到并丢弃字节，但永远不解密。保密是内层协议的职责（用 `mtls`/`tls`/`wss` 内层 dialer）；relay 是传输，不是信任。

**数据报通道**同样是明文：IP 包经 relay 或打洞路径不加密传输，而且与隧道不同，本宿主里没有东西给它加密（GOST 的 `tls`/`mtls` dialer 对 `udp` 隧道不适用）。仅在可信链路上使用，或在链路之上自行加密。

## Roadmap

1. ~~STUN + UDP 打洞隧道~~——已交付（KCP + smux 直连，DERP relay 回退）。
2. rendezvous 地址发现——已放弃：derper v1.102.3 只向 mesh watcher 发送 `PeerPresent`，从不发给开放中继客户端，因此基于 presence 的名字发现不可行。peer 以 base64 公钥寻址；人类可读名字应放在 GOST 配置里，而非 p2p 侧的注册表。
3. 数据报通道（tun/tap 走隧道）——已交付（`network=udp`）：每 peer 一个 UDP endpoint，成帧后走直连或 relay 的持久流。设备本身归 GOST（`tun` listener/handler），本宿主只是管道。

## License

MIT
