# p2p peer down/up：怎么读 `peer session killed` 与 `relay session rebuilt`

这两行是同一个 peer 的一次断链的两个半边。它们**不是**一一对称出现的日志对，
所以先记住规则，再看字段。

## 配对规则（先读这段）

- **一次断链 = 一条 `relay session rebuilt`。** 两条重建路径都会发这一条。
- **`relayReason` 空串 = smux keepalive 把会话判死，没有任何 kill。** 非空 = 本端主动 kill。
- **有 kill 必有 rebuild**：kill 会关掉 adapter，重建只能走 `peerConn` 换一个新 adapter。
  所以「有 `peer session killed`、找不到配对的 `relay session rebuilt`」= **这次断链没有自愈**。
- **rebuild 无 kill 是常态，不是 bug。** 静默判死（keepalive 超时）在 relay 侧
  **一个字都不打**（accept loop 只在 direct 传输时报错），主路径上唯一的信号就是
  rebuild 那一行。看到孤立的 rebuild，不要去补 kill、不要以为丢了事件。

## 字段

`relay session rebuilt` 现在自带一次断链的三件事：

| 字段 | 含义 |
| --- | --- |
| `relayReason` | 会话结束的原因；空串 = 静默判死（见上） |
| `downFor` | 从**观察到死亡**到打出这行日志的时长 —— 也就是「这次断链持续了多久」。**不含**重建握手本身：日志先打，session 后建 |
| `silentFor` | 从 pair 最后一次收到 underlay 数据报，到观察到死亡之间的时长 |

`silentFor` 决定了这行日志怎么读：

- `silentFor` 接近 0 → 死亡是突发/主动的（kill 触发），看 `relayReason`；
- `silentFor` 明显大于 0 → peer 先静默了一会儿才被判死，这是**链路问题**的形状
  （黑洞、WiFi 切 4G、relay 断），不是软件把它踢了。

`silentFor=0` 也可能是「引擎当时没有 pair 可测」—— 没有 recency 可读，原因有三个，
都不是「peer 一直说到死」：

- **pair 从来没建过**（peer 还从没走过 relay）；
- **pair 已经被更早的一次事件删掉**（六个 kill reason 会重置 pair 的 KCP epoch 并
  `delete(e.relayKCPs, peer)`）—— 注意是**更早**的那次：这一次死亡读 recency 的时机
  刻意选在 `dropRelayKCP` 之前，否则这次死亡会把自己的测量值一起抹掉；
- **pair 刚刚才收到过数据报**，也就是静默时长真的≈0。

所以 `silentFor=0` 是「说不出」而不是「没静默」；要区分只能看这一行之外的东西。

没有观测到死亡时（例如换了实现路径），这行只带 `relayReason`，不带两个时长 ——
零值时间会被渲染成一个「从公元 1 年算起」的荒谬时长，所以宁可不给。

## 例子

```
peer session killed  peer=Hpv9… relayReason=peer-rekeyed dropSecure=false sessionAge=32.1s gen=41
relay session rebuilt  peer=Hpv9… secureReuse=true desyncStreak=0 sessionAge=32.4s gen=41 \
    relayReason=peer-rekeyed downFor=312ms silentFor=298ms kcpConv=7 …
```

peer 换了密钥 → 主动 kill → 立刻重建，键复用。`silentFor≈downFor` 说的是「它说到死为止，
然后才被换掉」，跟 `silentFor=9s downFor=9.4s` 的「先静默 9 秒，然后超时判死」是完全不同的两件事。

## 不要做的事

- 不要因为「rebuild 没有配对的 kill」就给静默判死补一条 kill 日志 —— 现状就是设计。
- 不要用 `downFor` 当恢复耗时；它是死亡到**重建开始**的时长。
- 不要用 `pc.lastFrameAt`（relay 专属）解释 `silentFor`：peer 迁到 direct 之后它就陈旧了，
  日志里的值取自 pair 两个 underlay 的较新者。

## 关联记录

- 真机上这套行的实际样子、以及 `relayReason=peer-rekeyed` 的观测：
  `.memory/notes/p2p-relay-fix-verified-on-real-machine.md`
- 重建后 secure 层失步的老问题（`desyncStreak` 是怎么用的）：
  `.memory/notes/p2p-relay-rebuild-secure-poison.md`
- 设计与实现计划：`docs/superpowers/specs/2026-10-08-p2p-peer-down-events-design.md`、
  `docs/superpowers/plans/2026-10-08-p2p-peer-down-events.md`