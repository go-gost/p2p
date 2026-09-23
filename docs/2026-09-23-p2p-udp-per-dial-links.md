# p2p udp: one datagram link per dial

Status: **implemented** (2026-09-23, uncommitted). The link model, the
`serveInbound` routing, the Listen datagram delivery, the removal of the
notice/opener/channel machinery, unit tests and docs (CLAUDE.md, both READMEs,
docs/embedding.md) all landed; `-race` green over four consecutive full-package
runs, and **both e2e scenarios pass** (`udp-tun` 6/6, `udp-outlet` 4/4, real
derper + two netns, run in a privileged container — see the e2e notes below).

Three deviations/additions from the design below, found while implementing:

1. **The first-datagram flush is asynchronous** (`go l.flush()` in `publishOwn`
   and `adopt`): a flush can block on a peer that is not reading yet, and it
   must not stall the presenter or the adopter. Ordering still holds: `wmu`
   keeps the buffered bytes ahead of anything written later.
2. **In the two-sided shape the larger key's provisional presentation may be
   discarded by the smaller key**, so datagrams written before the rendezvous
   settles can still be lost — the same build-window loss the endpoint model
   had, and irrelevant to a tun link. The one-sided shapes (wisper entrypoint →
   reverse side, spoke → outlet) have no such window: the first-datagram buffer
   flushes straight to the dialer's own presentation, which the peer serves.
   Tests express the window by waiting for the larger key's adoption.
3. **`publishOwn` and `adopt` re-check the link state under the lock** (a link
   that already holds an adopted edge refuses a new presentation/adoption), and
   a refused `adopt` leaves the conn to the caller, which serves it per stream
   (the `serveInbound` fallthrough).

This continues the wisper UDP stage (a udp-serving reverse side + a p2p udp
entrypoint) and fixes the three data-plane defects the
[wisper integration doc](https://github.com/go-gost/wisper/blob/main/docs/p2p-integration.md)
measured and listed under "Known limitations".

## Why

Today a udp tunnel is **one channel per peer** (`internal/host/udp.go`): the
channel pairs "the newest dial's stream" with a peer edge (last dial wins), and
the peer edge is opened by whichever side owns the smaller key (`ch.loop`, or a
notice-driven opener loop on the pure-target side). Three defects were measured:

1. **Cross-talk between clients (R3)**: N concurrent dials share one peer edge
   and the local edge is replaced by the latest dial — c2 receives c1's in-flight
   replies and c1 receives nothing.
2. **First datagram always lost (R2)**: the peer edge attaches asynchronously, so
   `pumpLocal` silently drops bytes during the build window (48 of 50 runs lost
   the first datagram).
3. **The one-sided shape (wisper's reverse side) never receives a stream**: a
   `P2PU`-tagged inbound stream is only resolved as "channel → udp target →
   closed", so Listen/embedder mode gets nothing; and when the reverse side holds
   neither a target nor a channel, no side opens an edge if the *dialer* owns the
   larger key (the opener loop requires `targets.has("udp")`) — a **50% chance of
   a dead link**, dependent on key order.

The root cause is that the channel model ties "one dial" to "one peer": the udp
data plane needs **one link per dial** — the same shape a tcp tunnel has (one
dial, one stream).

## Decisions (settled)

1. **One link per dial**: `Dial`/`OpenTunnel(udp)` creates a link for that
   tunnel record. The per-peer channel, its reference count and `e.chans` are
   gone.
2. **The dialing side always presents**: every link opens its own `P2PU`-tagged
   edge as soon as it is allocated (asynchronously). **A failed presentation is
   not fatal** (Dial still succeeds when the relay is unreachable; the presenter
   retries with backoff, as before).
3. **Bounded first-datagram buffer (R2)**: local bytes read while no peer edge is
   live are buffered in the link (32 KiB, lazily allocated, new bytes dropped
   past the cap) and flushed in order once an edge is published. The lossy
   semantics are unchanged otherwise: only the "first edge is not up yet" window
   does not lose, everything after it still does.
4. **Adoption replaces the key-order opener**: an inbound tagged edge is adopted
   when **this host owns the larger key** and the peer's link has no live edge or
   is still on its own presentation. Anything else is served per stream (embedder
   → udp target → closed). The smaller key never adopts, so a pair with dials on
   both sides still rides **one shared edge** (tun-to-tun semantics unchanged),
   and the one-sided shape works whatever the key order (the wisper dead link
   disappears).
5. **The notice and opener machinery is deleted**: `ctrlDialUDP`/`sendDialUDP`,
   `startDatagramDialer`/`datagramDialerLoop`/`maxDatagramDialers`/`e.dialers`,
   `openChannel`/`attachLocal`/`release`/`channel`. **The wire is unchanged**: the
   `P2PU` tag and the 2-byte length-prefix framing stay exactly as they are.
6. **Listen delivers a datagram conn**: in Listen (embedder) mode a tagged stream
   is delivered as a **datagram conn** (`net.PacketConn`, frames parsed),
   `RemoteAddr` = the peer's base64 key. The embedder never sees the framing; tcp
   streams are delivered unchanged.
7. **Old/new interop** (no forced version lockstep):
   - New dialer + old responder: the new side always presents; the old side
     adopts it unconditionally (channel-first) or serves it per stream ✓. The old
     side no longer receives a notice and its pure-target opener loop never
     starts — it does not need to, because the new side presents ✓.
   - Old dialer + new responder: with a link, the new side adopts the old side's
     `ch.loop` presentation per the rule ✓; without a link (Listen/target), the
     old side still has to own the smaller key to present — the same limitation
     as old↔old, **not a regression** (the old larger key with a target-less
     responder was already dead).
   - The new side stops sending `ctrlDialUDP`; an old peer ignores the unknown
     control frame ✓.

## Design

### link (`internal/host/udp.go`, rewritten)

```
type link struct {
    e     *engine
    peer  derpclient.PublicKey

    stop     chan struct{} // closed by close(); ends the presenter
    done     chan struct{} // closed on teardown; the carrier parks here
    edgeGone chan struct{} // buffered(1): a peer edge died, the presenter re-presents

    wmu  sync.Mutex // serializes writes to the peer edge + the buffer drain
    wbuf []byte     // first-datagram buffer; capped

    mu       sync.Mutex
    local    net.Conn // this dial's tunnel stream; nil until the carrier attaches
    peerEdge net.Conn // current peer edge: our presentation or an adopted one
    own      net.Conn // our presentation edge; nil once adopted or dead
    closed   bool
}
```

- **presentLoop**: while the link has no edge, `openTaggedStream(peer)` →
  `publishOwn`; wait for the edge to die (or be adopted), then retry with
  `channelRetryMin`/`channelRetryDelay` (a presentation that lived resets to the
  fast floor, an open failure backs off). A link holding an adopted edge presents
  nothing — a second presenter would fight the shared edge.
- **adopt(c)**: closes the superseded presentation, publishes c, starts its
  reader, flushes. Refused (link closed, or an adopted edge already live) →
  false, and the caller keeps c.
- **serveEdge(c)**: the edge's only reader: bytes → the local edge (dropped while
  no carrier has attached); on exit it retires the edge (clears it, wakes the
  presenter).
- **pumpLocal(c)**: the local edge's reader: `writeEdge` per read; its exit
  closes the link (the dial's stream ending IS the dial ending).
- **writeEdge(p)**: under `wmu`, drain the buffer first, then write p to the
  current edge; with no live edge, append to the buffer (drop past
  `linkBufLimit`).
- **close()**: idempotent; stops the presenter, closes local/own/edge, closes
  `done`. Called by the record's drop and by the local pump's exit.
- **engine**: `links map[PublicKey][]*link` (a host may hold several links to one
  peer; the rendezvous shape has one) with `addLink`/`removeLink`/
  `adoptableLink` (the key-order half of the adoption rule).

### Dial and presentation timing

`allocateTunnel(udp)` — shared by both carriers — creates the link and starts the
presenter **asynchronously**. It is deliberately not a synchronous presentation
in `Dial`: `OpenStream` may block in `punchAndWait` on the first dial, and that
wait must not become Dial latency. The first-datagram buffer makes the window
length irrelevant.

### serveInbound (`internal/host/direct.go`, tagged branch)

```
if tagged:
    if lnk := e.adoptableLink(peer); lnk != nil && lnk.adopt(c, transport):
        return
    if q := e.inbound.Load(); q != nil:            # Listen: datagram conn
        q.deliverDatagram(c, peer, transport, peerAddr, e.log); return
    if target, ok := e.targets.pick("udp"); ok:    # pure target outlet
        e.serveTargetStream(c, target); return
    c.Close()                                      # no home (redundant presentations)
```

### Listen datagram delivery (`internal/host/inbound.go`)

- `frameConn` gains `ReadFrom`/`WriteTo` (forwarding to `Read`/`Write`, the same
  adapter `x/dialer/udp/conn.go` has) so it satisfies `net.PacketConn`.
- `inboundDatagramConn` (inboundConn's datagram twin) provides the PacketConn
  shape without giving it to tcp streams: `Accept` picks the type by the queue
  entry's `datagram` flag, so the local handler's `conn.(net.PacketConn)` test
  classifies correctly.
- `deliverDatagram` wraps the stream in `frameConn` and enqueues it as a
  datagram entry; tcp streams keep the old `deliver`.
- Contract docs: `docs/embedding.md` (Listen), both READMEs, `CLAUDE.md`.

### Deleted

- `direct.go`: the `ctrlDialUDP` constant (kind 0x03 is retired; the number is
  not reused), `sendDialUDP`.
- `engine.go`: the `ctrlDialUDP` case in `handleControl`, the `e.dialers` map,
  the `stopDatagramDialer` call in `peerGone`; `Close` tears down links.
- `udp.go`: the whole channel model (`openChannel`/`channel()`/`attachLocal`/
  `release`/`teardown`/`stopped`/`setStream`/`clearStream`/`clearLocal`/
  `serveStream`/`pumpLocal`/`startDatagramDialer`/`datagramDialerLoop`/
  `stopDatagramDialer*`/`maxDatagramDialers`). Kept: `peekTag`/`prefixConn`,
  `serveTargetStream`, `openTaggedStream`, `channelTag`/`channelTagTimeout`,
  `channelRetryMin`/`channelRetryDelay` (the link's re-present backoff reuses
  them), and `linkChunkSize` (renamed from `channelChunkSize`).
- `server.go`/`stream.go`: `record.ch` → `record.link`; `dropTunnel` closes the
  link; `serveTunnel` attaches the stream as the link's local edge.

### Behavior that must not change

- **tun-to-tun** (`x/handler/tun`, `play/p2p-tun.yaml`): one shared edge, the
  reconnect cadence, lossy semantics, derper-kill survival.
- **udp target outlet**: one target per stream, zero per-peer state, no admission
  (the caller decides).
- Framing/tag unchanged; `OpenTunnel(network=udp)` validation and error types
  unchanged; no udp in stub mode.
- `Status` gauges unchanged.

### Consumer impact

- **wisper**: the reverse side's `Listen` now yields datagram conns → its
  `peerListener.deliver` must use `stats_wrapper.WrapPacketConn` for a
  `net.PacketConn` (x's `WrapConn` would strip the shape); the entrypoint uses
  `x/dialer/udp` unchanged.
- **x/p2p (gRPC plugin path)**: no interface change (`OpenTunnel`/`AttachTunnel`
  semantics are the same); zero diff in x.
- **Version**: p2p **v0.5.0** (one control kind retired; the data-plane framing is
  unchanged; interop per decision 7).

### Non-goals

- Multi-peer fan-out (hop multi-node + selector), GOST-side session multiplexing
  (a session id in the frame), udp in stub mode.
- **Mixed topologies are unsupported**: when one peer both dials udp and accepts
  several udp dials from this host, the pairing is unlabeled (one link ↔ one peer
  link), so the extra edges land on the embedder/target or are closed. Documented.

## Tests

Unit (`internal/host`, in-process relay, `-race`):

1. `TestUDPTwoDialsIsolated` — two dials to one peer, each gets its own echo
   (R3); the first datagrams are written before either edge is up, so it also
   covers R2 for the outlet shape.
2. `TestLinkBuffersFirstDatagram` / `TestLinkBufferCapDrops` — the buffer holds
   the first datagram and is bounded.
3. `TestLinkAdoptReplacesPresentation` / `TestEngineAdoptableLink` — the
   adoption matrix: the larger key adopts (including replacing its own
   presentation), the smaller never does, an adopted edge is never displaced.
4. `TestLinkRepresentsAfterEdgeDeath` — a dead presentation is re-presented.
5. `TestListenDeliversDatagramConn` — the Listen conn satisfies
   `net.PacketConn`, carries the peer key, and round-trips datagrams.
6. `TestSpokeReachesTargetOutlet` (both key orders), `TestTunToTunBothKeyOrders`,
   `TestUDPTunnelEndToEnd`, `TestPeekTag`, `TestEngineIdleStreamBridged`,
   `TestLinkRetryDelay`, `TestLinkCloseIdempotent`.

e2e (`tests/e2e/run.sh`, real derper + two netns + real binaries):

- `udp-tun` and `udp-outlet` must not regress. The scenario's log assertion was
  updated from `channel up|channel role` to `datagram link up`.
- The N-client isolation e2e belongs to **wisper** (`tunnel/p2p_udp_poc_test.go`,
  tag `p2ppoc`) — that is the product path; the p2p unit tests cover the engine
  side.

## Tasks

### Task 1: the link type (present/adopt/re-present/buffer/teardown) + unit tests

- [x] Step 1: write the failing tests (`TestLinkBytePipe`,
      `TestLinkBuffersFirstDatagram`, `TestLinkBufferCapDrops`,
      `TestLinkAdoptReplacesPresentation`, `TestEngineAdoptableLink`,
      `TestLinkRepresentsAfterEdgeDeath`, `TestLinkCloseIdempotent`;
      `TestChannelRetryDelay` renamed `TestLinkRetryDelay`)
- [x] Step 2: implement the link in `internal/host/udp.go`; wire
      `server.go`/`stream.go`
- [x] Step 3: `gofmt` + `go build ./... && go vet ./...` + `GOWORK=off go build ./...`
      + `CGO_ENABLED=1 TMPDIR=/config/tmp go test -race -p 1 ./internal/host/`
- [ ] Step 4: commit

### Task 2: serveInbound routing + Listen datagram delivery + unit tests

- [x] Step 1: write the failing tests (`TestUDPTwoDialsIsolated` (R3),
      `TestListenDeliversDatagramConn`, `TestSpokeReachesTargetOutlet` for both
      key orders, `TestUDPTunnelEndToEnd` without the edge wait)
- [x] Step 2: rework the tagged branch in `direct.go`; the datagram conn in
      `frame.go`/`inbound.go`
- [ ] Step 3: verify + commit

### Task 3: delete the notice/opener/channel machinery + rework the old tests

- [x] Step 1: clean up per the delete list; rework
      `hub_test.go`/`lifecycle_test.go`/`udp_test.go`
- [x] Step 2: full `-race` unit tests + build/vet (both modes)
- [ ] Step 3: commit

### Task 4: e2e + docs

- [x] Step 1: `tests/e2e/run.sh --scenario udp-tun` and `--scenario udp-outlet`
      must not regress (in this container: a privileged Docker container with
      prebuilt binaries, `nicolaka/netshoot` for the tool set — apt mirrors are
      unreachable from here)
- [x] Step 2: update `CLAUDE.md`, `README.md`/`README.zh-CN.md`,
      `docs/embedding.md`
- [ ] Step 3: commit + release v0.5.0 (confirm the interop note before tagging)
