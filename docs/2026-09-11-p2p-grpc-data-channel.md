# P2P: replace the local endpoint with a gRPC data channel

## Context

The p2p plugin exposes its data plane as a **local dialable endpoint**: the host
process (`p2p/`, module `github.com/go-gost/p2p`) binds an ephemeral listener on
`--bind` and returns `host:port` in `OpenTunnelReply.endpoint`; the GOST client
(`x/p2p/tunnel_dialer.go:153`) then does `DialContext(endpoint)`. That only works
when the caller and the p2p host share a host/network — a firewall between them
blocks the inbound port and the plugin becomes unusable.

Fix: carry tunnel data over the **already-established GOST→host gRPC control
connection** (outbound, so it passes the firewall) using a bidirectional stream.
Per the user's decisions, the **endpoint data plane is removed entirely** — the
host stops listening per tunnel; only `--forward` static port-forwards keep a
local listener. One firewall port, one connection, clearer semantics.

This is the "exit ②" the origin design doc anticipated
(`p2p/docs/2026-09-05-p2p-plugin-stub.md:63,111`). Breaking wire change: the
`plugin` module must be released and re-pinned, and host + client must be
upgraded together (see "Release steps").

### Decisions (from the user)
- **Remove the endpoint**; the gRPC stream is the only data channel.
- **Keep `OpenTunnel`** as the **control/setup** RPC — it no longer returns an
  endpoint; it now does authorization, allocates a tunnel `id`, and negotiates
  `network` up front. The `id` gives observability (`Status`, per-tunnel logs)
  and binds the data stream to an authorized tunnel.
- **Drop `CloseTunnel`**: the `Tunnel` stream's lifetime IS the tunnel's
  lifetime — the stream ending is the close. A record whose stream never arrives
  is reclaimed by the pending GC. **The two replacement teardown paths (stream
  end, pending GC) must re-establish everything `CloseTunnel` used to do** —
  most importantly `channel.release()` for udp, whose ONLY caller today is
  `CloseTunnel` (`p2p/server.go:183`). See §5.
- **Support TCP + UDP** — final scope. Sequenced: **Phase 1 ships TCP only**;
  Phase 2 ships UDP (the tun link, `play/p2p-tun.yaml`). Phase 1 answers
  `network=udp` with `codes.Unimplemented` so there is no silent dead path.
- **Real `Set*Deadline`** on the stream-backed conn (the prior rejection reason:
  inner tls/ws handshakes call `SetDeadline` and ignore the error → a stalled
  peer hangs the handshake forever). Real on the GOST side; the host side
  cannot abort a server stream, so write deadlines there report "not supported"
  (§2) — host bridging code never sets them.

> Security model: the token gates **`OpenTunnel` only** (the existing unary
> interceptor covers it). `OpenTunnel` returns a **cryptographically random,
> single-use `id`** bound to the authorized `{peer, network}` — that id IS the
> **tunnel credential**. The `Tunnel` handler authorizes the stream by looking
> the id up (`NotFound` if unknown/expired), so the shared token need not be
> re-checked on the stream. This is *better scoped* than the token: the id lives
> only from `OpenTunnel` to stream end and cannot be replayed afterwards.
> Conditions: (a) the id must be unguessable — **not** the current `tunnel-%d`;
> (b) the id is a secret, so logs record only a short prefix, never the full id;
> (c) `OpenTunnel` must stay token-gated, else anyone can mint an id. Optional
> defense-in-depth: the client's per-RPC credentials already attach the token to
> every RPC, so a `StreamInterceptor` token check is nearly free — keep it if you
> want two factors.

---

## Phase 1 — TCP over the gRPC stream

### 1. Proto (`plugin/p2p/proto/p2p.proto`, module `github.com/go-gost/plugin`)
Keep `OpenTunnel`; **drop the `endpoint` field and `CloseTunnel`** (the stream's
lifetime is the tunnel's lifetime). Add a bidi stream RPC.

```proto
// OpenTunnel authorizes a tunnel, allocates a random id (observability + the
// stream credential), and negotiates the network. No endpoint is returned.
message OpenTunnelReply {
  bool ok = 1;
  string id = 2;
  reserved 3; reserved "endpoint";  // removed with the endpoint data plane
  string error = 4;                 // human-readable reason when ok == false
}
message Chunk { bytes data = 1; }   // one frame of a Tunnel byte stream

service P2P {
  rpc OpenTunnel(OpenTunnelRequest) returns (OpenTunnelReply);
  // Tunnel carries the tunnel's data; the server binds it to the tunnel named
  // by the "id" gRPC metadata key issued by OpenTunnel. The stream's lifetime
  // IS the tunnel's lifetime — there is no CloseTunnel: the stream ending
  // (EOF/error, or the server handler returning) tears the tunnel down.
  rpc Tunnel(stream Chunk) returns (stream Chunk);
  rpc Status(StatusRequest) returns (StatusReply);   // now a real tunnel count
}
```
Delete the `CloseTunnel*` messages (breaking change; nothing else references
them). Regenerate with the **pinned toolchain** in the file header (protoc
v3.15.8, protoc-gen-go v1.28.1, protoc-gen-go-grpc v1.2.0); keep the
`--proto_path=.` full-relative-path form (see `plugin/CLAUDE.md` — bare names
collide at init).

### 2. Stream `net.Conn` — `x/p2p/streamconn/conn.go` (new package, x module)
The **GOST side's** conn: deadlines, framed udp mode, abort. **Not in
`plugin/`** — that module holds contracts only (proto), and the p2p host
cannot import the `x` module, so the two sides couple through the proto
(Chunk messages), not through shared code. Not shared with the two existing
gRPC-stream conns either (`x/dialer/grpc/conn.go`, `x/listener/grpc/server.go`):
both speak protos under `x/internal` — unifying would mean relocating those
protos and changing the gRPC transport's wire format. Out of scope;
`x/dialer/grpc` keeps its "deadline not supported" stubs unchanged.

The **host** gets its own minimal raw conn (`p2p/streamconn.go`, package main):
one Recv pump with the same cap-1 handoff so `Close` can wake a parked `Read`
— a reader parked inside `Recv` could only be woken by the stream ending, and
that is exactly the case `Close` must handle (the peer EOFs while the client
is idle, and the handler cannot return to end the RPC while its pipe is
blocked). Raw bytes only (no framing — udp frame bytes travel through
untouched), no write deadlines (a server handler cannot abort its stream; its
return is the abort — verified against grpc-go v1.83.2: `WriteStatus` →
`finishStream` → `s.cancel()` unblocks a parked `Recv`, with a grpc-go comment
saying that exists for exactly this pattern).

**Framing:** the GOST-side conn carries its own `WriteFrame`/`ReadFrame`/
`MaxFrame` for the framed (udp) mode; the peer datagram channel keeps its copy
in `p2p/frame.go`. In udp the GOST side's frames cross the host as raw bytes
and are parsed by the peer channel's `ReadFrame`, so the two formats MUST stay
wire-compatible — note the coupling in both files.

- `type Stream interface { Send(*proto.Chunk) error; Recv() (*proto.Chunk, error); Context() context.Context }`
  — satisfied by both `proto.P2P_TunnelClient` and `proto.P2P_TunnelServer`.
- `New(s Stream, abort func(), network string, local, remote net.Addr) *Conn`
  — `abort` (the client stream's `cancel`) is what makes Close effective and
  write deadlines real; with nil (server streams) write deadlines report
  "not supported".
  - `network == "udp"`: **framed mode** — `Read` assembles one 2-byte BE frame
    across Chunks (the host pipes with `io.Copy`, so a frame can be split) and
    returns exactly one datagram; `Write` frames the datagram, splitting the
    frame bytes at 32 KiB if needed. This is what `x/dialer/udp/conn.go` needs
    (it derives `ReadFrom`/`WriteTo` from `Read`/`Write`, one datagram per
    call). Framed mode is used ONLY on the GOST side: the host always uses raw
    mode and stays a byte pipe (§Phase 2), so no double framing.
  - `network == "tcp"`: raw byte-stream mode.
- **Backpressure (bounded):** one `Recv` pump goroutine hands off to `Read`
  through a **cap-1 chunk channel** — the pump blocks on send while the consumer
  is behind, so a stalled local reader stalls `Recv` and gRPC/HTTP-2 flow
  control propagates to the sending peer. Memory is bounded at ~2 chunks.
  (A pump that appends to an unbounded buffer would decouple `Recv` from `Read`
  and defeat flow control — do not do that.)
- **Deadlines:** `Read` selects on the chunk channel / read-deadline timer /
  ctx / closed and returns `os.ErrDeadlineExceeded`; a deadline set while a
  Read is parked wakes it (replaced wake channel) and is re-evaluated. `Write`
  splits at 32 KiB (< gRPC's 4 MiB default), serializes `Send` on a mutex;
  when `abort != nil` a write-deadline watchdog calls `abort()` (killing the
  stream — a write timeout is fatal by nature); with `abort == nil`
  `SetWriteDeadline`/`SetDeadline` return a "not supported" error while
  `SetReadDeadline` still works.
- **Close (idempotent, `sync.Once`):** mark closed, `abort()` if non-nil, wake
  `Read` (closed channel), store the terminal error, unblock the pump's send.
  `Close` never waits for the pump; the pump funnels every exit (Recv error,
  ctx cancel, closed) through one path that stores the error and closes `done`
  — an abandoned reader would hang the host's pipe. Buffered chunks are
  drained before the terminal error is returned.

### 3. Client provider (`x/p2p/plugin/grpc.go`)
The GOST-side interface stays **one method** — the two-RPC dance is hidden here.

- `TunnelProvider` (`x/p2p/tunnel_dialer.go:26`):
  ```go
  type TunnelProvider interface {
      OpenTunnelStream(ctx context.Context, network, peer string) (net.Conn, error)
      Close() error
  }
  ```
- `grpcPlugin.OpenTunnelStream`:
  1. `reply, err := p.client.OpenTunnel(ctx, &proto.OpenTunnelRequest{Peer: peer, Network: network})`
     — business failure (`!ok`) → error; capture `id`.
  2. `sctx, cancel := context.WithCancel(context.Background())` (the conn
     outlives `Dial`, so the stream ctx must NOT be the dial ctx);
     `sctx = metadata.AppendToOutgoingContext(sctx, "id", id)`;
     `stream, err := p.client.Tunnel(sctx)`.
  3. wrap with `streamconn.New(stream, cancel, network, nil, nil)` — `cancel` is
     the `abort`; the conn's `Close` just returns `abort()` + closes the stream
     — the host treats the stream ending as the tunnel ending.
  - Token needs no work — `NewGRPCConn` injects it via `PerRPCCredentials` on stream RPCs too.
  - If step 2 fails, drop the id; the host's pending GC reclaims the record.
- Only `OpenTunnel` remains as the plugin's internal call; the public
  `TunnelProvider` shape changes. `NewGRPCPlugin(name, addr, opts...)` is unchanged.

### 4. Dialer (`x/p2p/tunnel_dialer.go`)
- `tunnelBaseDialer` collapses to: on first `Dial`, `d.pr.OpenTunnelStream(ctx,
  tunnelNetwork(network), d.peer)`, cache the conn, return. Delete
  `endpoint`/`id` state, the udp announce hack, and `tunnelConn` (the shared
  `Conn`'s Close is already idempotent).
- `tunnelDialer.Dial` failure path
  (`x/p2p/tunnel_dialer.go:88-95`): close `base.conn` **only if it was opened**
  — `OpenTunnelStream` can fail before any conn exists, and closing a nil
  `net.Conn` interface panics. Replace the current `base.tunnelID()` guard with
  a nil/once-guarded close on the base dialer (e.g. `base.closeTunnel()`).
  If no conn was opened there is nothing to close: the host's pending GC
  reclaims the record.
- `SupportedDialer` / `tunnelNetwork` / `Handshake` / `Multiplex` unchanged.

### 5. Host (`p2p/server.go`, `p2p/main.go`)
- **`OpenTunnel`** (keep, reworked): validate `network`/`peer` as today, but
  `network=udp` now answers `codes.Unimplemented` ("udp tunnels ship in Phase 2")
  — Phase 1 has no udp data path. For tcp: allocate a cryptographically
  **random** `id` (16 random bytes, base64url) and create a tunnel **record**
  `{id, peer, network, createdAt, attached bool}` (reuse `s.tunnels` under
  `s.mu`); start a **pending GC** that drops records with `!attached` older than
  a short timeout (e.g. 10 s), so a client that never opens the stream cannot
  leak. Return `{ok:true, id}` — **no endpoint**. No listener is created and no
  channel is opened in Phase 1.
- **No `CloseTunnel`** — replace it with one helper, **`dropTunnel(t)`**, that
  mirrors today's `CloseTunnel` body verbatim:
  `if t.ch != nil { t.ch.release() } else { t.close() }` (plus removing it from
  `s.tunnels`). Both new teardown paths call it:
  - the `Tunnel` handler returning (stream EOF/error, or host-side teardown), and
  - the pending GC.
  `channel.release()` is refcounted, so releasing one tunnel's reference must
  never close a channel another live tunnel still holds — never call
  `ch.teardown()`/`ch.sock.Close()` from these paths.
- Extract the listener-independent core of `(*tunnel).bridge` (`server.go:217`):
  - `openPeer(engine *Engine, peer, target string) (net.Conn, error)` — `engine.OpenStream`
    (DERP) or `net.DialTimeout(target)` (stub).
  - `pipe(conn, up net.Conn, endpoint, target string)` — the half-close +
    `trackConn` + `"<endpoint> <-> <target>"` logging.
  `(*tunnel).bridge` becomes a thin wrapper (behavior unchanged for `--forward`).
  Behavior parity note: today's p2p base conn (`tunnelConn`) has no `CloseWrite`,
  so `halfCloseWrite` already full-closes it; the stream-backed conn full-closing
  too is NOT a regression (and `xnet.Pipe`-style callers see the same semantics).
- Add `p2p/stream.go`: `func (s *server) Tunnel(stream proto.P2P_TunnelServer) error`
  — read `id` from `metadata.FromIncomingContext(stream.Context())`, look up the
  record (unknown/expired → `status.Error(codes.NotFound, ...)`) — **peer and
  `network` come from the record, not the stream, so the client cannot spoof
  them**; mark the record attached in the same critical section as the lookup,
  and reject a second stream for the same id (`AlreadyExists` — the id is
  single-use); wrap the server stream with the host's own minimal conn
  `newStreamConn(stream, nil)` (`p2p/streamconn.go`; raw byte pipe, no abort);
  `openPeer` + `pipe(conn, up, "stream:"+shortID(id), peer)`.
  On return: `dropTunnel(record)` — stream end IS the teardown. The handler
  must **return promptly once `pipe` ends and must not wait for the conn's
  pump goroutine**: the return triggers `s.cancel()` (grpc-go `finishStream`),
  which unblocks the pump's parked `Recv`; waiting on it instead would deadlock.
- Remove the per-tunnel listener path (`startTunnel` stays **only** for
  `--forward`). `Status` counts records.
- **Auth:** the token (existing `UnaryInterceptor`, `main.go:202`) gates
  `OpenTunnel` only. The `Tunnel` handler authorizes the stream by `id` lookup —
  no `StreamInterceptor` needed. Optional defense-in-depth: the client's per-RPC
  credentials already attach the token on stream RPCs, so a
  `streamAuthInterceptor` on `grpc.StreamInterceptor` is nearly free; add it if
  you want two factors.

### 6. Config / docs
- No config field added. **`--bind` becomes inert in Phase 1** and is removed in
  Phase 2 (its readers were: `server.go:109` per-tunnel listener — deleted here;
  `udp.go:55` channel socket — live again only in Phase 2). Correct the earlier
  claim that it feeds `--forward` or the STUN/direct source IP: it does neither
  (`--forward` uses the spec's listen addr, `server.go:165`; the direct punch
  binds via `bindAddrFor(e.stunAddr)`, `direct.go:340/549`). Keep the flag
  parsing for one phase so existing configs don't break, log a deprecation
  warning at startup, and delete flag + config field + `p2p/CLAUDE.md` row in
  Phase 2.
- Update `p2p/CLAUDE.md` (control/data plane: OpenTunnel no longer returns an
  endpoint), `plugin/CLAUDE.md` — the p2p service table row AND line 46 "All
  RPCs are **unary** (no streaming)": `Tunnel` is the module's first streaming
  RPC, so that invariant line must change to name the exception — and proto
  comments.

---

## Phase 2 — UDP datagrams over the gRPC stream (tun)

Separate, larger phase; shippable after Phase 1. Ships only if the tun link must
work cross-host. **All Phase 2 teardown must go through the Phase 1 `dropTunnel`
helper** — the udp record's `ch` reference is what `CloseTunnel` used to
release.

- **GOST side:** `streamconn` framed mode (§2) makes the returned conn
  datagram-preserving, so `x/dialer/udp` needs no change.
- **Host side (`p2p/udp.go`):** the `channel`'s local edge is today a
  `sock net.PacketConn`; the gRPC stream takes its place, and the host pipes it
  raw (`io.Copy` both ways, via `p2p/streamconn.go`'s `streamConn`). Framing
  stays a GOST-side concern: GOST's framed conn emits frame bytes, the host
  copies them verbatim, and the peer channel's `ReadFrame` (`p2p/frame.go`)
  consumes them; the reverse path is the same. The empty-datagram
  client-announce hack falls away (the stream, not a client address,
  identifies the local edge).
  - `channel` keeps its refcount and `loop`/`serveStream`; drop `sock`,
    `readLocal`, and the `client` address tracking. `OpenTunnel(network=udp)`
    opens the channel again (refs=1, `record.ch`) and returns the id; the
    `Tunnel` handler pairs with it, and its `dropTunnel` release is the ONLY
    refcount decrement.
  - Opener (smaller key): on a gRPC `udp` stream, `engine.OpenStream(peer)` +
    `P2PU` tag + pipe (reuse `channelTag`/`peekTag`).
  - Responder: `acceptLoop` receives the tagged peer stream; pair it with the
    local GOST's gRPC stream **for the same `id`/peer** (a rendezvous map, since
    the endpoint address no longer carries the pairing). Attach whichever side
    arrives last; the `OpenTunnel` record is the rendezvous point.
  - Multiple dials per peer is out of scope: last stream wins, as the endpoint
    path's last-client-wins does today.
- Remove `--bind` (flag, config field, `main.go:165/189` plumbing,
  `p2p/CLAUDE.md` row) — `udp.go`'s `ListenPacket` was its last reader.
- `network=udp` requires DERP mode (unchanged, `server.go:72`).

---

## Files

Landing: on approval, save this plan to
`p2p/docs/2026-09-11-p2p-grpc-data-channel.md` (project convention:
date-prefixed plan docs under `p2p/docs/`).

| Action | Path |
|---|---|
| edit | `plugin/p2p/proto/p2p.proto` (+ regenerate `p2p.pb.go`, `p2p_grpc.pb.go`) |
| new | `x/p2p/streamconn/conn.go` (GOST-side conn + `WriteFrame`/`ReadFrame`/`MaxFrame`) (+ `conn_test.go`) |
| new | `p2p/streamconn.go` (host-side minimal raw stream conn) |
| edit | `x/p2p/tunnel_dialer.go` (interface + base dialer simplification + failure-path nil guard) |
| edit | `x/p2p/plugin/grpc.go` (OpenTunnelStream: OpenTunnel→id→Tunnel stream) |
| edit | `x/p2p/plugin/grpc_test.go` (fakeServer: OpenTunnel + Tunnel stream) |
| edit | `p2p/server.go` (OpenTunnel rework, `dropTunnel`, `openPeer`/`pipe`, record lifecycle) |
| new | `p2p/stream.go` (`Tunnel` handler) (+ `stream_test.go`) |
| edit | `p2p/main.go` (`streamAuthInterceptor` + `grpc.StreamInterceptor`, `--bind` deprecation warn) |
| edit | `p2p/udp.go` (Phase 2: stream edge, drop sock/readLocal) |
| edit | `p2p/CLAUDE.md`, `plugin/CLAUDE.md` (incl. the unary-RPC line) |
| edit | `p2p/go.mod`, `x/go.mod`, `gost/go.mod` (plugin/x re-pins, see below) |

## Release steps (required before the `GOWORK=off` builds can pass)

The plan adds packages and RPCs to the `plugin` module, which `p2p` and `x` pin
by version (`p2p/go.mod:7`, `x/go.mod:14` — both `github.com/go-gost/plugin
v0.7.0`; `gost/go.mod:52` carries v0.6.1 indirect). In-workspace `go.work`
builds resolve the local module and mask this, so:

1. Tag `plugin` (breaking proto change → **v0.8.0**, not a patch).
2. Bump `p2p/go.mod` and `x/go.mod` to it; `go mod tidy` each.
3. Then — and only then — run the `GOWORK=off` build/test in Verification.
4. On x release, bump `gost/go.mod`'s x pin (and let tidy fold the indirect
   plugin pin).

## Verification
- `cd plugin && go build ./... && go vet ./...`; `cd x && go build ./... && go vet ./...`.
- After the Release steps: `cd p2p && GOWORK=off go build ./... && CGO_ENABLED=1 go test -race ./...`.
- Unit: `x/p2p/streamconn` deadline + **backpressure** tests (fake `Stream`; assert the
  pump blocks with the cap-1 channel — e.g. it does not issue a second `Recv`
  while the first chunk is unconsumed); `x/p2p/plugin/grpc_test.go` stream
  round-trip + read deadline + "`OpenTunnel` called exactly once per tunnel";
  `p2p/stream_test.go` bridge round-trip + **auth regression** (unknown/expired
  id → `NotFound`; if the optional stream token check is enabled, missing token →
  `Unauthenticated`) + **teardown regression** (handler return unblocks the
  stream conn; pending GC reclaims an unattached record) + Phase 1 udp is
  `Unimplemented`.
- E2E (nested netns, two netns mandatory — `p2p-e2e-nested-netns` memory):
  `play/p2p.yaml` (tcp) end-to-end. `play/p2p-tun.yaml` is **Phase 2** (real tun
  + derper, ping both ways, one `channel up` per side in the log).
- Confirm **no per-tunnel listener** remains: host log shows no ephemeral
  `endpoint`; `ss -ltn` shows only `--addr` (and `--forward`).

## Risks
1. **`id` is a stream credential** — it must be cryptographically random and
   treated as a secret (never logged in full; log a short prefix). The current
   `tunnel-%d` scheme is guessable and MUST NOT be reused. `OpenTunnel` stays
   token-gated, else anyone can mint an id. Optional: a stream token check as a
   second factor (nearly free). Regression-tested.
2. **Pending-record lifecycle** — `OpenTunnel` without a following stream (the
   client died between the two calls) must be GC'd on a timeout; that GC — plus
   the stream-end path — are the ONLY cleanup now that `CloseTunnel` is gone,
   and both MUST route through `dropTunnel` so a udp record's channel reference
   is released (a leaked `ch` holds a UDP socket + goroutines; a wrongly
   torn-down `ch` kills a concurrently-live tunnel to the same peer). Main new
   complexity; keep the timeout short, log reclaims.
3. **Breaking proto + release** — `endpoint`/`CloseTunnel` removed; `plugin`
   must be tagged and re-pinned in `p2p` and `x` before `GOWORK=off` builds
   pass; host + client upgrade together.
4. **Deadline semantics** — a write timeout cancels the whole stream (a net.Conn
   write timeout is effectively fatal); the host side has no real write deadline
   (can't abort a server stream) and reports "not supported"; server streams
   can't `CloseSend`, so a peer EOF truncates the reverse direction (same as
   today's DERP path). Host-side wakeups rely on the handler returning
   (`finishStream` → `s.cancel()`), so the `Tunnel` handler must never block on
   the pump goroutine.
5. **Head-of-line blocking** — all tunnels share one HTTP/2 `ClientConn`, so a
   wedged TCP connection affects every tunnel (per-stream flow control still
   isolates a stalled stream except at the TCP layer).
6. **Message size** — writes split at 32 KiB; a future larger buffer must stay
   under gRPC's recv limit.
7. **Phase 2 pairing** — the responder's gRPC stream ↔ inbound peer datagram
   stream rendezvous is new coupling in `p2p/udp.go`; needs its own e2e.
