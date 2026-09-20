# p2p:transport 统计(direct vs relay)暴露到 gRPC Status —— 实现计划

## 背景(Context)

2026-09-12 的 NAT 调研结论:对称 NAT(EDM,含大量 CGNAT)下打洞必失败 → **永久 relay**;在多对一 hub 场景里这会放大成"每个 spoke 对都退化成 relay"。当时定的推进顺序是:

1. **先加"直连 vs relay 命中统计"** —— 现在完全没有指标,用它判断后续投入是否值得;
2. 再决定要不要做 IPv6 直连 / PCP-NAT-PMP-UPnP 端口映射。

本计划只做第 1 步。

现状:`OpenStream` 已经给每条流打了 transport 标签(`"direct"` / `"derp"`,[engine.go:197](../engine.go#L197)/[:211](../engine.go#L211)/[:250](../engine.go#L250)),入口侧 `acceptLoop` 同样带 `transport` 参数([direct.go:647](../direct.go#L647))。但这些标签**只进日志**,既无聚合也无查询口。

已有的 seam(不新造):

- 契约里 `Status(StatusRequest) → StatusReply` **已存在**([server.go:291](../server.go#L291)),`StatusReply.tunnels` 字段注释写明 *"future path/status fields are added here"* —— 这就是预留的扩展点;
- `server` 结构体**已持有** `engine *Engine`([main.go:186](../main.go#L186) `newServer(engine)`),而 direct/relay 状态就在 Engine 里,所以无需新接线。

决定:用现有 gRPC `Status` RPC 承载,**不开新输出通道**(不加日志汇总行、不加 HTTP 端点、不加新子命令)。调用侧开 gRPC reflection,用 `grpcurl` 手动查询。

## 设计

### 1. 契约:新字段(新增字段号,向后兼容)

`StatusReply` 追加 6 个字段。契约只放定义(`plugin/`,模块内不放逻辑),生成代码随 protoc 输出。

| 字段 | 号 | 类型 | 含义 |
|---|---|---|---|
| `direct_peers` | 2 | int32 | **gauge**:当前存活直连的 peer 数 |
| `derp_peers` | 3 | int32 | **gauge**:当前仅 relay(无存活直连)的 peer 数 |
| `punch_attempts` | 4 | int64 | **counter**:累计打洞尝试 |
| `punch_success` | 5 | int64 | **counter**:累计打洞成功 |
| `streams_direct` | 6 | int64 | **counter**:累计走直连的流(出+入) |
| `streams_derp` | 7 | int64 | **counter**:累计走 relay 的流(出+入) |

`streams_*` 两侧都计:出向在 `OpenStream`,入向在 `acceptLoop`。`punch_*` 只在出向(只有发起打洞的一侧有 punch 状态机)。

gauge 报"现在是直连还是 relay",counter 报"打过几次洞、成几次"——两者合起来才能区分**"环境不支持打洞" vs "打了但失败"**,而这正是决定要不要做 IPv6 的判断依据。

### 2. 计数源:Engine(atomic)

counter 在事件点自增,gauge 在查询时实时算。

### 3. 关键正确性点:gauge 不能用 `session()`

`dc.session()` **有副作用**:发现会话已死会 teardown + 触发重打洞([direct.go:158-179](../direct.go#L158-L179))。gauge 查询若调它,会让一次 `Status` 调用**顺便触发重打洞**,语义错误。

必须新增一个**纯读**探针 `dc.live() bool`:`state == directUp && sess != nil && !sess.IsClosed()`,不动任何状态。

### 4. 锁序

`transportCounts()` **先在 `e.mu` 下快照** `directs`/`peers` 的指针切片,**释放 `e.mu` 后**再逐个调 `live()`(取 `dc.mu`)。这样不存在 `e.mu → dc.mu` 的持有嵌套,也就**不会引入任何新的锁序问题**。

## 改动

模块归属:`plugin/` 只改契约(proto + 生成代码),逻辑全部在 `p2p/`。

### Task 1 —— 契约:`plugin/p2p/proto/p2p.proto`

1. `StatusReply` 追加上表 6 个字段(号 2-7)。
2. 从 **`plugin/` 模块根**执行(不能在 proto 子目录里跑,否则注册裸文件名,见 `plugin/CLAUDE.md`):

```bash
protoc --proto_path=. --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    p2p/proto/p2p.proto
```

本地 `protoc 3.15.8` + `protoc-gen-go` + `protoc-gen-go-grpc` 已在位,与 pin 一致。

**门禁**:`cd plugin && go build ./... && go vet ./...`;`git diff` 确认只有"新增字段 + 生成代码对应部分",无意外重排。

### Task 2 —— 计数源:`p2p/engine.go`(+ `p2p/direct.go` 探针)

1. `Engine` 加 `stats engineStats` 字段(`engine.go:34` 结构体);`engineStats` 用 `sync/atomic`:
   - `punchAttempts, punchSuccess, streamsDirect, streamsDerp`(int64)
   - `snapshot()` 返回四个值。
2. 自增点:
   - `directConn.punch()` 入口([direct.go:330](../direct.go#L330))→ `punchAttempts++`。
   - `dc.state = directUp` 处([direct.go:262](../direct.go#L262))→ `punchSuccess++`。
   - `OpenStream` 三个返回点([engine.go:197](../engine.go#L197)/[:211](../engine.go#L211) direct、[:250](../engine.go#L250) derp)→ `streamsDirect/streamsDirect/streamsDerp` 各 `++`。
   - `acceptLoop` 入口([direct.go:647](../direct.go#L647),已有 `transport string` 参数)→ 按 `transport` 自增。
3. 新增 `func (dc *directConn) live() bool`,紧邻 `session()`;纯读,不 teardown、不调度。
4. 新增 `func (e *Engine) transportCounts() (direct, derp int)`:按上文"锁序"实现——`e.mu` 下快照两个 map 的 key 切片 → 解锁 → 逐个 `dc.live()` 数 direct;对 `peers` 里**不在** live-direct 集合中的数 derp。

### Task 3 —— 暴露:`p2p/server.go` `Status`

```go
func (s *server) Status(ctx context.Context, req *proto.StatusRequest) (*proto.StatusReply, error) {
    reply := &proto.StatusReply{Tunnels: int32(len(s.tunnels))}
    if s.engine != nil { // stub 模式(--derp 未设)engine 为 nil → 其余字段留 0
        reply.DirectPeers, reply.DerpPeers = s.engine.transportCounts()
        reply.PunchAttempts, reply.PunchSuccess,
            reply.StreamsDirect, reply.StreamsDerp = s.engine.stats.snapshot()
    }
    return reply, nil
}
```

`direct_peers` 与 `derp_peers` 之和 = 当前与之有会话的 peer 总数(一个 peer 若直连存活即归 direct,不计入 derp)。

### Task 4 —— 调用:`p2p/main.go` 开 reflection

在 `grpc.NewServer(...)` 之后、`s.Serve` 之前加一行:

```go
reflection.Register(s) // import "google.golang.org/grpc/reflection"
```

注意:`--token` 非空时,reflection(stream RPC)也会走 `streamAuthInterceptor`([main.go:434](../main.go#L434)),所以此时 `grpcurl` 要带 `-H 'token: …'`。loopback 默认(空 token)直接可用。

### Task 5 —— 文档

- `p2p/CLAUDE.md` + `p2p/README.md`(+ `README.zh-CN.md`)加一小节"查询 transport 统计",给出 `grpcurl` 命令与字段释义。

## 测试(p2p 模块,全部 `-race`;既有 74 个测试保持全绿)

| 测试 | 断言 |
|---|---|
| `TestDirectLiveNoSideEffect` | 造 `state==directUp` + 已关闭 `sess`,`live()` 返回 false,且 **`state` 仍为 `directUp`**(证明没 teardown、没重打洞);对照 `session()` 会把 state 归 `directNone` |
| `TestEngineStats` | 走 punch / OpenStream 路径后,counter 按预期递增 |
| `TestStatusNoEngine` | `engine==nil` 不 panic,只回 `tunnels`,其余 6 字段为 0 |
| `TestStatusCounts` | 造 directs/peers 状态,gauge 归类正确(含"直连 peer 不计入 derp") |

`CGO_ENABLED=1 go test -race ./...`。

## E2E

复用嵌套 netns 脚本(`/tmp/e2e-*` 体系)起两端 + derper,`grpcurl -plaintext <addr> proto.P2P/Status` 拉一次,断言 `direct_peers` / `punch_attempts` / `streams_*` 有值且自洽(punch_success ≤ punch_attempts)。

## 风险 / 边界

- **gauge 只在有活跃会话时非零**:idle 的 peer 不计入,符合"当前实际路径"的语义。
- **单 peer 双路径**:direct 与 relay 会话可能并存;按"有 live 直连即算 direct"归类,不重复计数。
- **锁**:Task 2 的快照-后-探测实现,避免 `e.mu` 持有期间取 `dc.mu`,无新锁序。
- **契约兼容**:`x/p2p/plugin`(`grpc.go`)只调 `OpenTunnel`/`Tunnel`,不调 `Status`;新增字段对它是纯增量,编译与运行都安全。
- **不新增依赖**:`reflection` 在 `google.golang.org/grpc` 内,已在依赖里。

## 发布

- `plugin` `v0.8.0 → v0.8.1`(契约新增字段);
- `p2p/go.mod`、`x/go.mod` 的 `github.com/go-gost/plugin` 跟随 bump(依赖链);
- `p2p` 自身出 `v0.2.x`。

## 工作顺序与门禁

Task 1(契约) → 2(计数源) → 3(暴露) → 4(reflection) → 5(文档)。

每步:`go build ./... && go vet ./...`;测试 `CGO_ENABLED=1 go test -race`。

## 自检

- [ ] gauge 走的是新增的只读 `live()`,**没有**调有副作用的 `session()`——有回归测试兜底。
- [ ] `engine == nil`(stub 模式)不 panic——有测试。
- [ ] 未新增任何依赖。
- [ ] 契约改动只在字段号 2-7,旧客户端行为不变。
- [ ] proto 从 `plugin/` 模块根 regen,文件名不是裸 `p2p.proto`。

## 不做(YAGNI)

per-peer 明细、HTTP/JSON 端点、`p2p status` 子命令、打洞耗时直方图、Prometheus metrics 端点。

> `p2p status` 子命令的触发条件:真的嫌 `grpcurl` 麻烦时再建。
