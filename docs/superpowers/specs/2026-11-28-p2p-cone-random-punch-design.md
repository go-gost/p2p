# p2p Cone ↔ Random 蜂窝直连（birthday fallback）设计

- 日期：2026-11-28
- 状态：草案（待批准）
- 仓库：`p2p`
- 关联：`wisper` 的 tun/p2p 入口；实测记录见根工作区 `.memory/notes/wisper-cellular-direct-options.md`

## 1. 为什么要做

2026-11-28 在真实网络实测（Pixel 9 蜂窝 ↔ 家宽 pi）：

- 手机蜂窝：同一 socket 打 4 个 STUN → `39.144.43.60:3049 / 30526 / 38266 / 6042`，**每目的地映射不同**；300 个 socket 打同一 STUN → 端口按 **62 个一组、组间 +620** 分配，组内 +1，**每组起始 base 随机**。结论：手机是 **RandomSymmeric**（EDM）。UU 的 `ConePunchToRandomSymmeric` + `RandomSymmericPunchToCone` 正是为这种形状准备的。
- 家宽：同一 socket 打 4 个 STUN → 恒定 `61.170.218.121:4847`，即 **EIM / Cone**。
- 真实 spike：pi（Cone）用 p3 `61.170.218.121:2970` 向手机公网 IP 的 **1000 个随机端口**喷；手机（Random）开 **150 个 socket**（`SO_BINDTODEVICE rmnet1`）向 p3 发 seed；**第一轮命中**，client idx=46、local `10.20.158.208:55922`、**211ms**。
- 现有 p2p 只有「单 STUN、单 socket、Cone↔Cone」的普通打洞；蜂窝上必然回落 relay。UU 的 3×3 矩阵里，本网络落在 `Cone → Random` 这一格。

## 2. 目标 / 非目标 / 反目标

**目标**

- 在「本端 Cone、对端 Random（每目的地随机 base）」时，p2p 能在蜂窝上建立直连；失败仍回 relay。
- 用 p2p 现有的 seed 握手、`directUnderlay`、KCP/QUIC 数据面，不引入新传输。
- 两个方向都支持：家宽/服务端（spray 侧）与手机/客户端（sockets 侧）。
- 默认关闭，opt-in，capability 协商；旧 peer 不受影响。

**非目标**

- 不做完整 3×3 矩阵（`LinearSymmeric`、`BothLinear`、`BothRandom` 留到后续）。
- 不做 NAT 自动分类/UI；本版用显式角色配置（家宽 `spray`，手机 `sockets`）。
- 不改 relay（DERP/WSS）、不改 IPv6（手机已有 v6，但 hub 没有；v6 仍是另一条独立路径）。
- 不把 relay 改成 UDP；不做 TCP 打洞。

**反目标**

- 不对任意公网 IP 扫描端口；只对已经通过 relay 认证、且通过 caps 明确 opt-in 的 peer 的公网 IP 发包。
- 不默认开启；不在每轮普通 punch 都喷；不在失败后无限喷。
- 不破坏现有「Cone↔Cone」的快速路径与 relay 优先/质量回退。

## 3. 方案对比

| 方案 | 成本 | 结果 |
|---|---|---|
| A. 原生 IPv6 | 零代码，需 pi 拿到全局 v6 | 手机已有 v6；hub 没有；仍是最好的长期解，但本设计不依赖它 |
| B. `ConePunchToLinearSymmeric`（50 个预测端口） | 低 | 实测手机每目的地 base 随机，预测无效；只适用于跨目的地全局顺序的 CGNAT |
| C. 非对称 birthday（本设计） | 中：多 socket + 随机端口 + seed 扩展 | **实测第一轮命中**；本网络唯一可用的 v4 路径 |
| D. 继续 relay | 零 | 可用，但不是直连；保留为兜底 |

选定 **C**，A 作为并行推荐（用户可先开 IPv6；不阻塞本设计）。

## 4. 设计

### 4.1 配置

新增 `p2p.Config.Punch *PunchConfig`：

```go
type PunchConfig struct {
    // Mode 选择本端在 fallback 中的角色。"" / "off" = 不启用；"spray" = 本端是 Cone 侧，
    // 从同一个打洞 socket 向对端公网 IP 的随机端口喷；"sockets" = 本端是 Random 侧，
    // 开多个 socket 向对端 p3 发 seed。
    // 家宽/服务端配 "spray"，手机/客户端配 "sockets"。
    Mode string `yaml:"mode,omitempty"`

    AfterRounds  int           `yaml:"afterRounds,omitempty"`  // 连续普通轮失败多少次后进入 fallback，默认 1
    SprayPorts   int           `yaml:"sprayPorts,omitempty"`   // 每轮随机端口预算，默认 1000，上限 2048
    SprayEvery   time.Duration `yaml:"sprayEvery,omitempty"`   // spray 轮间隔，默认 2s
    Sockets      int           `yaml:"sockets,omitempty"`      // sockets 侧 socket 数，默认 150，上限 512
    SocketWindow time.Duration `yaml:"socketWindow,omitempty"` // sockets 侧总窗口，默认 20s
    SeedGrace    time.Duration `yaml:"seedGrace,omitempty"`    // 先完成一侧继续回显对端 token 的宽限，默认 500ms
}
```

- 上限在 `applyDefaults`/校验里夹住；`SprayPorts=0`、`Sockets=0` 用默认值；负数/非法字符串报错。
- 现有 `Config.Direct`、`Config.Stun` 语义不变；`Punch.Mode` 为空时完全走旧路径。
- `cmd/p2p` 增加 `--punch-mode`、`--punch-spray-ports`、`--punch-sockets` 等 flag（与 yaml 同名）。
- wisper：hub 的 `p2p` 配 `punch.mode: spray`；手机的 `p2p` 配 `punch.mode: sockets`；`p2pHostConfig`/`p2pHostSig` 带上该字段，改动后重建 host。

### 4.2 capability

新增 `capsSpray uint8 = 1 << 4`（bit 0 IPv6、bit 1 retired、bit 2 `capsNoDirect`、bit 3 `capsQUIC`；bit 4 空闲）。语义：

- `Mode` 为 `spray`/`sockets` 时在 `ctrlCaps` 里置位；每次候选广播重发（幂等，OR 累积）。
- 只有对端也置位时，本端才进入 fallback；否则按旧路径重试/relay。
- 旧 peer 不认这个 bit：不置位、也不会进入 fallback；不会收到 spray（本端只在看到对端 bit 后才喷）。
- `capNames`/doctor 增加 `spray`。

### 4.3 角色与触发

- `directConn` 记录连续普通轮失败数（复用 `failGen`/`failed` 的语义，新增 `fallbackRounds` 计数）。
- 当 `AfterRounds` 次普通轮失败、双方 caps 都置位、且 peer 有公网 IPv4 时，下一轮走 fallback。普通轮失败后若 fallback 已武装，用 `dc.retry(fallbackRetry=500ms)` 而不是 30s 的 `dc.backoff()`，让第一次 fallback 在普通轮 5s 超时后很快发生。
- fallback 轮仍走 `dc.noteRound`/trace；失败后回到普通 backoff；成功安装后清空失败计数。
- fallback 依赖双方的 IPv4 候选：spray 侧需要自己的 STUN p3（同一 socket），sockets 侧需要自己的公网 IPv4（供 spray 侧定位）；任一侧没有公网 IPv4 时跳过 fallback，回 relay。
- 角色决定：
  - 本端 `Mode=="spray"`：单 socket（现有 `collectV4` 的 socket/p3）+ 随机目标集合；
  - 本端 `Mode=="sockets"`：多 socket + 对端 p3；
  - 两端同时运行，不需要额外的信令轮次；caps 已保证双方都启用。

### 4.4 spray 侧（Cone）

- 复用 `collectV4` 的 socket（必须是做 STUN 的同一个 socket，保证 p3 一致）。
- 目标：对端 **公网 IPv4**（从 `peerV4` 中选出的第一个公网地址，而不是列表末尾——末尾可能是 loopback/私网；若只有本地候选则跳过 fallback）的 `SprayPorts` 个随机端口（1024–65535，去重，`math/rand` 每轮新集合）。
- 本端自己的 p3 来自 `collectV4` 的同一个 socket；spray 必须在这个 socket 上发，否则对端 filter 里的 p3 与源端口不一致，包会被丢。
- 每 `SprayEvery` 把 `seedProbeMagic+token` 发到整个目标集合一次；总窗口 `SocketWindow`（默认 20s）或直到成功。1000 个包/2s ≈ 500pps，有上限。
- 同一 token 由现有 `seedHandshakeUDPToken` 生成；目标集合作为新的 `targets []netip.AddrPort` 参数；对端 probe 仍回显到 source，learn-and-retarget 保留。
- 命中后 `seedOutcome.Answer` 是手机映射 `q_i`；`markUp` 用该 socket + `q_i`。

### 4.5 sockets 侧（Random）

- 开 `Sockets` 个 UDP socket，全部绑定到 `bindAddrFor(stunAddr)` 的 egress IP（与现有 `collectV4` 相同的源地址选择）。第一个 socket 就是现有 `collectV4` 的打洞 socket（这样它的 STUN 公网候选仍然有效），其余是新 socket；不需要为每个新 socket 再问 STUN。
- 每个 socket 向对端 p3（`peerV4` 的公网候选）每 `seedRetransmit` 发自己的 token；监听；收到对端 token 就回显；收到自己的 token 即成功。
- 第二个 socket 之后不需要再问 STUN：对端 p3 已知，自己每个 socket 的映射由 NAT 分配；这正是 Random 侧要的。
- 如果 `collectV4` 失败（STUN 不可达/没有公网候选），sockets 侧无法把自己的公网 IPv4 交给 spray 侧，fallback 跳过（relay）；这是已知依赖，后续可用多 STUN 解决。
- 成功后把赢家 socket 交给 `markUp`；其余 socket 关闭；`SocketWindow` 到期全部关闭并回普通 backoff。
- 先 `2s` 延迟（`SprayEvery`）再开 socket，给 spray 侧先发第一轮，减少「socket 先到、spray 还没开」的空窗。

### 4.6 seed 扩展

`seedHandshakeUDPToken` 增加一个变体（或参数化）：

- `targets []netip.AddrPort`：每 `seedRetransmit` 轮询发送（spray 侧用 `SprayEvery` 控制整集合频率，单目标重传仍 200ms）。
- `responderGrace time.Duration`：自己已收到 token 之后，继续把对端 token 回显到 source，持续 `SeedGrace`，再返回。原因：spray 命中时先完成的一侧可能是 spray 侧；对端的 token 探针要等它自己的下一次重传才到，若立即返回并安装 underlay，会把对端 seed 当数据。
- 现有的「无源过滤、learned 重定向、每个 probe 都回显」保持不变。
- 多 socket 版本每个 socket 一个 goroutine；谁先成功就取消其余；取消用 socket 关闭触发读错误，不用 context 也能收敛。

### 4.7 安装与数据面

- 与现有 `markUp` 完全一致：赢家 socket + `winOut.Answer` + token 交给 `directUnderlay`；KCP/QUIC 的 pair 会话不新建。
- spray 侧：`Answer` 是手机 `q_i`；sockets 侧：`Answer` 是 home p3。
- 输掉的 socket 在 `markUp` 前关闭；`closeFams` 的语义沿用。
- `directUnderlay` 的 source filter、idle watchdog、H2 loop guard 不变。

### 4.8 状态与诊断

- `PeerDiagnostic`/`Status` 增加（in-process）：`PunchFallback`（`""`/`spray`/`sockets`）、`FallbackRounds`、`SprayPorts`、`Sockets`、`Winner`、`LastFallbackErr`。
- `punch` trace 增加：`fallback spray ports=...`、`fallback sockets=...`、`fallback up via socket i`。
- doctor：`punch mode` 行；`caps` 加 `spray`；错误词不把「fallback 未启用」说成 symmetric NAT。
- wisper 的 `/api/p2p/doctor` 自动继承；UI 暂不新增开关。

### 4.9 安全与限流

- 只对经过 relay 认证的 peer；只对 peer 的公网 IPv4；目标端口随机、每轮上限 2048；`SprayEvery` ≥ 1s。
- 只在 `AfterRounds` 次失败后进入；成功后停止；`SocketWindow` 封顶；失败回普通 backoff。
- 记录发包数/命中数；日志不打印 token/完整端口集合（只打印数量/首个端口/是否命中）。
- 已知风险：CGNAT 共享 IP 的随机端口可能落到其他订阅者的映射；包内容只有 seed magic+随机 token，对非本 peer 无意义；仍应在文档/配置里标注，默认关闭。

## 5. 测试

- **单元**：
  - `PunchConfig` 默认值/上限/非法值。
  - caps：`Mode` 为空不置位；spray/sockets 置位；旧 peer 不置位时 fallback 不进入。
  - 随机目标集合：数量、范围、去重、每轮不同。
  - 多目标 seed：fake UDP 对端；spray 侧/ sockets 侧都能完成；`responderGrace` 在「先完成一侧」时仍能回显对端 token（红→绿）。
  - 多 socket 取消：赢家安装、输家关闭、无 goroutine 泄漏。
- **引擎**：fake peer + 两个 localhost UDP 端点，模拟 cone/random 的映射；`AfterRounds` 触发、fallback 成功、失败回 backoff。
- **e2e netns**：现有 `p2p/tests/e2e` 加一个 `nat-cone-random` 场景：家宽侧 `MASQUERADE`（port/cone），手机侧 `MASQUERADE --random-fully`（random symmetric）；两端 `punch.mode` = spray/sockets；断言 `direct` 建立；对照组（fallback off）仍是 `derp`。这是能抓住「普通 punch 失败」的回归。
- **真机**：pi + Pixel 9（蜂窝）；spike 已验证网络，p2p e2e 用 wisper hub/APK 手动回归；记录 hub 日志 `direct established` 与 `fallback` 行。

## 6. 风险与限制

- **运营商行为**：1000 个随机端口可能触发限速/扫描检测；本设计默认 off、上限、间隔、成功后停止；实测首轮命中，但不同地区/时段可能不同。
- **手机耗电/射频**：150 个 socket + 750pps 的开销；只在蜂窝直连失败后短窗口运行，成功即停。
- **升级**：p2p → wisper go.mod → hub 镜像/APK；旧 peer 因 caps 不启用，仍走 relay；没有 wire 破坏（seed 包格式不变，caps bit 新）。
- **角色配置错误**：hub 配 sockets / 手机配 spray 会退化成普通 punch；doctor 明确显示角色；文档写清。
- **p3 变化**：spray 侧必须用同一个 STUN/打洞 socket；如果未来 `collectV4` 改多 socket，要保持 p3 与 spray 的一致性。
- **IPv6**：本设计不改变 v6；手机已有 v6，hub 没有；如果 hub 以后拿到 v6，v6 仍是优先路径。

## 7. 未决 / 后续

- 自动 NAT 分类（同 socket 多 STUN → Cone/Linear/Random）与自动角色；本版不做。
- `LinearSymmeric` 的 50 预测、`BothLinear`/`BothRandom`；本版不做。
- wisper UI 的开关/状态展示；本版只做 p2p 配置与 API/doctor。
- 端口喷发的运营商侧长期影响，需要上线后观察。
