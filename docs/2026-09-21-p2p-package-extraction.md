# p2p 包化重构计划(package main → 可导入库 + 进程内 Provider)

> Status: **Phase 1 + Phase 2 已实现(2026-09-21),门禁全绿,待提交/发布**。
> 目标读者:实施 agent。本文是唯一权威稿;`.memory/notes/p2p-engine-extraction-plan.md` 是进入 Plan 模式前的早期草稿,已过时,实施时按本文更新。

## Context

`github.com/go-gost/p2p` 目前是 `package main` + 独立 module,根目录全部是 `package main`,**任何模块都无法 import**,wisper 只能 spawn 子进程 + loopback gRPC 使用它。

目标是让 wisper(及后续 gost / 移动端)能**进程内内嵌**:单二进制、无需子进程、无需 loopback socket/token;同时 CLI 行为、数据面、协议完全不变,`x` 侧零改动。

## 已确认决策

| # | 决策 | 选择 |
|---|---|---|
| D1 | 布局 | 根包即库 `package p2p` + `cmd/p2p`(Option A) |
| D2 | 配置 | 复用现有 `Config` 类型;`New(cfg, opts...)` |
| D3 | 私钥 | 保留 `Config.Key`(文件路径),新增 `Config.KeyHex`(hex 32B),两者互斥 |
| D4 | 启动 API | `Connect` + `Start` + `Provider` 三分离 |
| D5 | 日志 | 注入 `*slog.Logger`(默认 `slog.Default()`),去掉库内全局 `slog` 依赖 |
| D6 | 范围 | Phase 1(包化+嵌入 Host)+ Phase 2(进程内 TunnelProvider)一起做 |
| D7 | 公开边界 | p2p **不 import x**;`Provider` 结构化匹配 `x/p2p.TunnelProvider`,断言放 wisper |
| D8 | network 归一化 | p2p 库内再归一化一次,不假设调用方已转 |

## 目标 API

```go
package p2p

type Config struct {
    Addr     string   // gRPC 控制面监听地址(CLI/远程用;内嵌可忽略)
    Token    string
    Derp     string   // DERP url;空 = stub 模式
    Key      string   // 私钥文件路径(与 KeyHex 二选一)
    KeyHex   string   // 新增:内存态私钥,hex(32B)
    Targets  []string
    Stun     string
    Direct   *bool
    TLS      *TLSConfig
    Log      *LogConfig        // 仅 cmd 解释,库不读
    Timeouts *TimeoutsConfig
    Forwards []ForwardConfig
}

func New(cfg *Config, opts ...Option) (*Host, error) // 纯构造,无 I/O
func WithLogger(*slog.Logger) Option                 // 默认 slog.Default()

func (h *Host) Connect() error                        // 连 DERP(stub no-op);失败返回 error
func (h *Host) Start() (addr string, err error)       // Connect + serve gRPC,返回实际地址(支持 :0)
func (h *Host) Serve(ln net.Listener) error           // 在调用方 listener 上服务
func (h *Host) Addr() string
func (h *Host) PublicKey() string                     // stub "";DERP base64
func (h *Host) AddForward(listen, peerKey string) error
func (h *Host) Status(ctx context.Context) (*proto.StatusReply, error)
func (h *Host) Provider() *Provider
func (h *Host) Close() error                          // 幂等

type Provider struct { log *slog.Logger; h *Host; closed atomic.Bool }
func (p *Provider) OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error)
func (p *Provider) Close() error                      // 不再接新流;不拆 Host
```

**内嵌用法(Phase 2):**
```go
host, _ := p2p.New(&p2p.Config{Derp: url, KeyHex: hex, Targets: []string{svc}}, p2p.WithLogger(log))
host.Connect()
registry.P2PRegistry().Register("p2p", host.Provider())
// chain node: Addr=对端 pubkey, Metadata{"p2p":"p2p"}, connector forward + dialer tcp
```

**CLI 用法(Phase 1):** `New` → `Start` → 等 signal → `Close`。gRPC/token/forward 全在,`x` 侧零改动。

## Phase 1:文件级迁移

| 动作 | 对象 |
|---|---|
| `package main` → `package p2p` | config/dgram/direct/engine/frame/server/stream/streamconn/target/udp + 全部 `*_test.go`(共 10 非测试 + 10 测试) |
| 抽出 `cmd/p2p/main.go` | flag 解析、config 合并、`setupLogger`/`parseLogLevel`/`logOutput`/`replaceAttr`/`levelString`(含 lumberjack)、信号处理 |
| 留在库内 | `buildTLSConfig`、`loadOrCreateKey`(扩展 KeyHex)、`defaultKeyPath`、`authInterceptor`、`streamAuthInterceptor` |
| 新增 | `host.go`、`provider.go`、`pipe.go` |
| 改造 | engine/server/stream 共 9 处 `slog.*` → 注入 `log`;`newServer` 由 Host 持有;`gcPending` 加 stop channel |
| 构建/脚本 | `.goreleaser.yaml` `main: .` → `main: ./cmd/p2p`;`tests/e2e/run.sh:119`;`CLAUDE.md` build 指令;README 安装路径 |

行为变化仅三处:`gcPending` 可停、`Host.Close` 真正关停 forward listener、logger 由全局变注入。

`Host.Close` 顺序(幂等):关 gRPC listener → 关 forward tunnel → `grpc.Stop` → `engine.Close` → 停 gc。

`Start` 语义保留现 CLI 行为:`Connect` 失败**仅告警继续**(重连 ticker 后台重试),不返回错误;需要严格错误用 `Connect()`。

## Phase 2:进程内 TunnelProvider

关键:`server` 已是 transport-agnostic,只差一层薄抽象。`streamconn.go` 已有 `tunnelStream` 接口(`Send/Recv/Context`),host handler(`proto.P2P_TunnelServer`)与测试 client 都满足它。

**1) 拆分「记录分配」与「服务一条流」**
```go
// server.go
func (s *server) allocateTunnel(network, peer string) (*tunnel, error) // OpenTunnel 与进程内共用

func (s *server) OpenTunnel(ctx, req) (*proto.OpenTunnelReply, error) {
    t, err := s.allocateTunnel(network, req.Peer)
    if err != nil { return nil, err }
    return &proto.OpenTunnelReply{Ok: true, Id: t.id}, nil
}

func (s *server) Tunnel(gs proto.P2P_TunnelServer) error {
    t, err := s.claimTunnel(idFromMetadata(gs)) // 解析 id + 标记 attached
    if err != nil { return err }
    defer s.dropTunnel(t)
    return s.serveTunnel(t, gs, nil)           // abort=nil:handler return 即结束
}
```

**2) handler body 泛化为 `tunnelStream` + `abort`**
```go
func (s *server) serveTunnel(t *tunnel, stream tunnelStream, abort func()) error {
    conn := newStreamConn(stream, abort)
    if t.network == "udp" {
        <-t.ch.attachLocal(conn)
        return nil
    }
    up, err := t.openPeer()
    if err != nil { abort(); return err }
    t.pipe(conn, up, endpoint, t.target)
    return nil
}
```

**3) 内存流对 `pipe.go`(保留 Chunk 边界,共享 ctx)**
```go
type pipeStream struct { ctx context.Context; send, recv chan *proto.Chunk }
func (p *pipeStream) Send(c *proto.Chunk) error   { select { case p.send <- c: return nil; case <-p.ctx.Done(): return p.ctx.Err() } }
func (p *pipeStream) Recv() (*proto.Chunk, error) { select { case c := <-p.recv: return c, nil; case <-p.ctx.Done(): return nil, p.ctx.Err() } }
func (p *pipeStream) Context() context.Context    { return p.ctx }
// newPipePair(ctx) -> (client, server):a.send→b.recv, b.send→a.recv
```

**4) Provider 接线**
```go
func (h *Host) OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error) {
    if h.providerClosed() { return nil, net.ErrClosed }
    t, err := h.server.allocateTunnel(normalizeNetwork(network), peer)
    if err != nil { return nil, err }
    streamCtx, cancel := context.WithCancel(context.Background()) // 流寿命独立于 dial ctx
    clientSide, serverSide := newPipePair(streamCtx)
    go func() { defer cancel(); _ = h.server.serveTunnel(t, serverSide, cancel) }()
    return newStreamConn(clientSide, cancel), nil // conn.Close() → cancel
}
```

`normalizeNetwork`: `udp/udp4/udp6`→`udp`,其余→`tcp`(对齐 `x/p2p.tunnelNetwork`)。

gRPC 与进程内**共用 `serveTunnel`**,唯一差别是流载体;datagram 语义天然保留(pipe 不粘连 Chunk)。**不 import x**:`Provider` 结构化匹配 `xp2p.TunnelProvider`;由 wisper 做 `var _ xp2p.TunnelProvider = host.Provider()` 断言(以及 `Close() error` 满足 io.Closer)。

不采用 bufconn:bufconn 只省 socket,仍需 proto client 复刻 x 插件逻辑;上述做法直接砍掉控制面,内嵌路径不存在地址/token/`NewGRPCPlugin`,连带消除 `logger.Default()` nil panic 的坑。

## 交付顺序

1. 改名 + `host.go` + `cmd/p2p` —— 行为不变,既有测试全绿。
2. 生命周期收口(`gcPending` stop、`Host.Close`、forward 关停)+ logger 注入。
3. Phase 2:`allocateTunnel`/`serveTunnel` 拆分 + `pipe.go` + `provider.go`。
4. 脚本/文档/CI + embedding 测试(进程内 provider 跑 stub 往返)+ e2e 回归。

## 验证门禁

```sh
GOWORK=off go build ./... && GOWORK=off go vet ./...
GOWORK=off CGO_ENABLED=1 go test -race -p 1 ./...
P2P_E2E=1 ./tests/e2e/run.sh            # 至少 stub / derp-relay
GOOS=linux   GOARCH=amd64 go build ./cmd/p2p
GOOS=windows GOARCH=amd64 go build ./cmd/p2p
GOOS=darwin  GOARCH=amd64 go build ./cmd/p2p
```

新增测试建议:
- `host_test.go`:stub 模式 `New`+`Start`(`127.0.0.1:0`)+ 进程内 `Provider` 开隧道 + echo。
- `Provider` 与 gRPC 路径 stub 往返结果一致的对照测试(防两路径漂移)。
- 现有白盒测试原样保留(同包)。

## 风险与兼容

- **Breaking**:根路径不再产出二进制。`go install github.com/go-gost/p2p@latest` 失效,改为 `.../cmd/p2p@latest`;README/CLAUDE 注明。版本号待定(候选 v0.4.0)。
- `internal/derpclient`/`internal/stun` 同 module,继续可用;**其类型绝不进公开签名**(`PublicKey()` 保持 string)。
- goreleaser 的 `before.hooks: go mod tidy`、`GOWORK=off` 门禁保持不变(已验证 tidy 为 no-op)。
- 移动端:lumberjack/文件日志只留在 cmd;库默认 stderr,无文件依赖。
- `Provider.Close()` 只停止接受新隧道,不拆 Host;已开流由各自 conn 生命周期收尾(与 gRPC 侧一致)。
- `hub_test.go`、`main_test.go` 命名是历史遗留(现为库测试),可选重命名,非必需。

## 未决项

- 版本号(v0.4.0?)与 tag 时机:实施完成后再定。
- `.memory/notes/p2p-engine-extraction-plan.md` 需在实施后按本稿更新;`wisper-p2p-integration.md` 的「进程外 spawn」结论届时改为「进程内」。
