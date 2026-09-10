# p2p 设备链：把已有设备（tun/tap/…）经 p2p 连成管道

## Context

目标：p2p host **不创建、不配置**任何网络设备，只**打开一个已存在的设备**（tun/tap），
把它的数据经 p2p 的**打洞直连 / relay 中继**路径与对端的同类设备互通，形成一条点对点链路。
本版只求端到端连通——加密、鉴权、控制面、虚拟地址分配、多 peer mesh、子网路由/exit node、
L2 泛洪、命名、多 DERP 全部后置。

**方案选择（B）**：设备由外部（运维脚本 / 其他工具）提前创建并配好地址/路由/MTU，p2p 只
attach。理由（见前几轮对比）：零新依赖、不经手宿主网络栈、保持 p2p 的窄定位、泵可注入测试。
代价：需外部先建好**持久且未被 attach** 的 tun/tap（`ip tuntap add dev X mode tun`，被别的
进程持有 fd 会 EBUSY；也正因如此**不能与 gost 的 tun listener 共用同一设备**），且打开路径
仅 Linux。

**泵是通用的**：打开后设备只被当作"chunk 设备"——泵不解析、不路由，只把每次 `Read` 到的
一段字节加 2 字节长度前缀发走，收到的拆帧写回设备。
- `packet → packet`（tun/tap）：包边界保住；
- `stream → stream`（pipe/socket）：字节流原样保住；
- 唯一不成立的是 `stream → packet`（流端任意大小的读会被当成一个个包写进 tun/tap，边界错乱）。
因此**要求两端同类设备**即可，泵里无需判断。
由此该特性泛化为"**把任意两个同类 chunk 设备用 p2p 连起来**"；本版 `openDevice` 只实现
Linux 的 tun/tap。

现状支撑：p2p 数据面是 smux 可靠有序字节流（direct KCP / relay TCP 之上），`OpenStream`
已优先直连、回退 relay，每 peer 会话有 keepalive 与重连——链路部分可直接复用。

## 配置（只用一个 flag）

**`--link "<device>=<peerkey>"`** —— 与 `--forward` 同形，左边换成设备引用：
- `--link "p2p0=<Bkey>"` → 打开名为 `p2p0` 的 **tun**（默认）；
- `--link "tap:veth0=<Bkey>"` → 打开 tap（左值前缀 `tun:` / `tap:` 指定类型，缺省 tun）。
- YAML 用 `links:`（与 flag 同形的字符串列表，累加、flag 覆盖，镜像 `forwards`）。

不再有独立的 `--dev` / `--dev.type`。启动校验：`--link` 需 `--derp`；设备链与 `--target`
（forward）互斥；本版**至多一条 `--link`**（多 peer 会并发写同一设备且无 L2 泛洪语义，超范围）。

## 设计

**打开设备 + 通用泵**（新 `p2p/dev.go`）
- `openDevice(name string, kind) (io.ReadWriteCloser, error)`，`kind ∈ {tun, tap}`。
- Linux 实现：`open("/dev/net/tun")` + `ioctl(TUNSETIFF, name | IFF_TUN|IFF_TAP | IFF_NO_PI)`。
  用 `golang.org/x/sys/unix`（已是 p2p 的间接依赖，**不新增下载**）。`IFF_NO_PI` 保证无 4 字节
  packet-info 前缀，读写都是裸帧/包。`kind` 是唯一需要参数化的地方，泵完全不动。
- 只**打开**设备 fd，**不配置**地址/路由/MTU（外部负责）。
- 泵：源→链 `for { n,_ := dev.Read(buf); if n>0 { send [2B n][buf[:n]] } }`；链→汇读 2 字节长度 +
  `io.ReadFull` 读满 + **循环写满设备**（`io.Writer` 允许部分写 `n<len`，最易漏的 bug）。缓冲区
  ≤ 64KB（2 字节上限）；丢弃 `n==0`；顺序/不丢由 smux 保证。

**单设备读循环 + 当前流指针**（关键坑）
- tun 的 `Read` **不支持 deadline**（gost 的 tun conn 亦如此）。若每个 stream 各起一个"设备→流"
  goroutine，流断开时该 goroutine 会**卡死在 `Read`** 上。
- 因此：**全局唯一一个** `devReadLoop` 持续读设备，写入"当前活动流"（`atomic.Pointer` 或互斥锁
  保护的指针）；断开期间丢弃包（IP 本就允许丢）。收到新流时替换指针。
- 反向"流→设备"按流起一个 goroutine，靠 stream 读错误退出；多读并发写设备安全。

**链路（角色与重连）**（新 `p2p/link.go`，或并入 engine.go）
- 每 `--link` 一条持久 stream；角色按公钥排序（小者发起），复用 `Engine.OpenStream`
  （direct 优先 / relay 兜底）。
- 发起方 `linkLoop`：`OpenStream` → 设为活动流 → 流结束后**退避重连**（复用 `backoffPeriod`）；
  `<-e.stop` 退出。应答方无新循环：复用 `acceptLoop`，设备模式下把入站 stream 设为活动流。
- 设备 fd 全程只打开一次，重连只换流；进程退出时关闭 fd（设备本身保留）。

**引擎接入**（`p2p/engine.go`）
- `Engine` 增 `dev io.ReadWriteCloser`（nil = 普通模式）与活动流指针；启动 `devReadLoop`。
- `acceptLoop`：设备模式下把入站 stream 交给"流→设备"路径，**不再**按 `--target` 桥接。

## 文件

- `p2p/dev.go` — 新增：`openDevice`（Linux tun/tap，x/sys）+ 分帧编解码 + 通用泵 + `devReadLoop`。
- `p2p/link.go` — 新增：`--link` 解析（`device=peerkey`）+ `AddLink` + `linkLoop`。
- `p2p/engine.go` — `Engine` 加 `dev` 字段与活动流指针；`acceptLoop` 设备模式分流；启动 `devReadLoop`。
- `p2p/main.go` / `p2p/config.go` — 单一 `--link` 接线 + `links:` + 校验。
- `p2p/CLAUDE.md` — flag 表 + 定位/信任模型补设备链说明。
- `p2p/go.mod` — 无新增第三方依赖（`x/sys` 由 indirect 转为 direct）。

## 非目标（本最小版）

- **不创建/不配置设备**：地址、路由、MTU、up 全归外部；p2p 只 attach。
- **无加密**（明文帧走 relay/打洞，等价明文链路）、无鉴权、无控制面、无虚拟地址分配、无多 peer
  mesh、无子网路由/exit node、无 L2 泛洪、无命名、无多 DERP。
- 每 host 一个设备、一条 `--link`；设备链与 `--target`/forward 互斥；`stream→packet` 不对应。
- `openDevice` 仅 Linux tun/tap（其它 `kind` 留作同一 seam 的后续扩展）。

## 验证

单测（`p2p/dev_test.go`，不碰真设备）：
- 用内存/`net.Pipe` 造两个假设备 + 一对流，断言 `pump` 双向字节保真：源端按**不规则大小**分段读、
  汇端**故意部分写**，验证分帧、`io.ReadFull` 补全、写满循环都正确。
- 覆盖 `packet↔packet`（保持每读一个包边界）与 `stream↔stream`（字节序列一致）两种配对。
- 链路：断言角色排序下仅小公钥一方发起；流断开后退避重连并恢复。
- `--link` 解析：`p2p0=Bkey`（tun）、`tap:veth0=Bkey`（tap）。

端到端（手工，Linux）：
```
# 两端各预先建好持久、未被 attach 的 tun 并配地址/up
ip tuntap add dev p2p0 mode tun && ip addr add 10.10.0.1/30 dev p2p0 && ip link set p2p0 up
p2p --derp wss://<derper>/derp --key A.key --link "p2p0=<Bkey>"
# 另一端 10.10.0.2/30
ping 10.10.0.2；跑一次 TCP/iperf 应通；杀掉 derper 后应走 direct 继续通。
```
tap 验证：两端 `--link "tap:<name>=<key>"` 且同网段（两节点=交叉网线；>2 节点不在范围）。

命令：
```
cd p2p && go build ./... && go vet ./...
cd p2p && GOWORK=off go build ./...
cd p2p && CGO_ENABLED=1 go test -race ./...
```
