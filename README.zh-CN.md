# p2p

[English](README.md) · **简体中文**

为 [GOST](https://github.com/go-gost/gost) 的 [p2p 插件](https://github.com/go-gost/plugin) 协议服务的隧道宿主进程。它让 GOST 通过本进程打开的隧道，建立到链节点的网络通路——穿越策略（rendezvous、relay、打洞）完全由插件决定，GOST 侧永远只看到一条本地可拨号的普通 endpoint。

**当前状态：stub + mux + DERP relay + STUN/UDP 打洞。** 宿主用本地 TCP 转发桥接隧道：stub 模式（回环）直接转发，**DERP relay** 模式（engine）跨机/NAT。engine 模式下，relay 会话建立后，两端各自用 STUN 探测 NAT 并打 UDP 洞；直连路径（KCP + smux）建立后，新隧道走直连、relay 保持为回退。支持内层 dialer `tcp/tls/ws/mtcp/mtls/mws`——mux 一族把一条隧道复用成多路会话。控制面支持可选 token 认证（`--token`）。

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

两端都在 engine 模式时，relay 只用于建立首条会话并承载控制面。后台每个 peer 向 derper 内建 STUN 服务器（默认端口 `3478`，`-stun` 默认开启）查询自己的公网 UDP endpoint，经 relay 与对端交换，并在同一 UDP socket 上建立 **KCP** 会话。成功后，新隧道在直连 smux 会话（KCP + smux）上开流；relay 会话保持，直连失败时静默回退 relay 并重新打洞。直连路径即使 relay 掉线也继续工作——只有 *新的* 打洞才需要 relay 回来。设置 `--stun` 时，预配置的 `--forward` 会在启动时预热其 peer 的直连路径，首个连接无需等待打洞。

对称 NAT 打洞失败；这类 peer 永久留在 relay（周期性重试）。KCP 传输不加密，与 relay 的信任模型一致——保密是内层 dialer 的职责（`mtls`/`tls`/`wss`）。

derper 的 STUN 服务器只应答 Tailscale 的 binding-request 方言（`SOFTWARE` + `FINGERPRINT` 属性），并绑定与 `-a` 相同的 IP。用显式 IP 运行 derper（`-a 1.2.3.4:443`），使 STUN 在对端要查询的地址族上可达；用通配 `-a :443` 时它会绑到 IPv6-only，默认的 IPv4 `--stun`（`derp host :3478`）够不着——此时需显式设置 `--stun`。

## 安全

控制面默认**未认证**：任何能访问 `--addr` 的进程都能让本宿主拨任意地址。让 `--addr` 保持回环（默认值）。跨机部署需设 `--token`（GOST client 以 gRPC metadata 发送）**且**配控制面 TLS——仅凭 token 目前走的是明文 gRPC 通道。

`-verify-clients=false` 的 DERP relay 是开放中继：它能看到并丢弃字节，但永远不解密。保密是内层协议的职责（用 `mtls`/`tls`/`wss` 内层 dialer）；relay 是传输，不是信任。

## Roadmap

1. ~~STUN + UDP 打洞隧道~~——已交付（KCP + smux 直连，DERP relay 回退）。
2. rendezvous 地址发现——已放弃：derper v1.102.3 只向 mesh watcher 发送 `PeerPresent`，从不发给开放中继客户端，因此基于 presence 的名字发现不可行。peer 以 base64 公钥寻址；人类可读名字应放在 GOST 配置里，而非 p2p 侧的注册表。

## License

MIT
