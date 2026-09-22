# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## What this is

The p2p library: a standalone P2P connectivity layer, and the host process for the GOST [p2p plugin](https://github.com/go-gost/plugin) control protocol (`github.com/go-gost/plugin/p2p/proto`). GOST calls `OpenTunnel(peer)` over gRPC, then carries the tunnel's data on the `Tunnel` bidi stream bound to the returned id — no local endpoint is opened per tunnel (a firewall between GOST and this host used to block it). The GOST side (`x/p2p/`) uses that stream as the base connection of any supported chain-node dialer.

Current implementation: **stub + mux + token + DERP relay + STUN/UDP hole punching + datagram channels + udp target outlet**. It proves the plugin seam end to end, supports inner dialers `tcp/tls/ws/mtcp/mtls/mws/udp` (mux inners reuse one tunnel as a session; udp asks for a datagram stream instead of a byte stream), has optional control-plane token auth, and — with `--derp` — relays tunnels cross-machine through a DERP server. After a relay session is up, both peers punch a UDP hole (STUN + KCP + smux) and prefer the direct path; the relay stays as fallback. Data-plane encryption is end-to-end (the inner protocol's job). A udp tunnel is a **datagram channel**: a rendezvous between a persistent peer-edge stream and one of two *ends* — a local GOST udp `Tunnel` stream (the per-peer `channel`) or a udp `--target` outlet (per-stream, stateless); the GOST-side conn frames the datagrams and the peer's GOST-side conn parses them, so this host never touches the framing (see Datagram channel below).

### Package layout (do not blur these lines)

| Package | Role |
|---|---|
| `p2p` (root) | **contracts only**: `Config` + `TLSConfig`/`ForwardConfig`/`TimeoutsConfig`, `Status`, the sentinel errors. **Standard library only** — a test (`deps_test.go`) fails if anything else creeps in. |
| `p2p/endpoint` | the public endpoint: identity, engine, forwards, `Dial`/`Listen`/`Status`. Owns the host; an embedder never holds it. |
| `p2p/grpc` | the gRPC transport: serves an endpoint over the plugin protocol (`OpenTunnel`, `Tunnel`, `Status`) and owns its listener + token check. Named after its protocol, so it aliases grpc-go as `ggrpc` inside itself. |
| `p2p/internal/host` | the host: engine, registry, data planes, and the **seam** (`OpenTunnel`/`AttachTunnel`/`Dial`/`Listen`). The package is unimportable outside the module, so third-party transports are not supported — a value obtained from `Endpoint.Host()` still has callable methods, but the seam is not a stable contract and changes without notice. |
| `cmd/p2p` | the CLI: flags, its own config-file format (`addr`/`token`/`log` + the inlined `p2p.Config`), and the assembly of endpoint + gRPC transport. |

Rules that follow from the layout: the root never learns a protocol or a config
file; a transport never learns the host's internals (it maps the root's sentinel
errors to its own codes); the endpoint owns the engine, a transport owns only
its own listener (closing one never touches the other).

### Positioning / contract boundary

`p2p` is a **P2P connectivity layer, not a turnkey secure tunnel**. The contract is deliberately narrow: *give a peer public key, get a TCP tunnel; NAT traversal best-effort (STUN + hole punch, relay fallback); reachability is ours, security is the caller's.* This mirrors IP/TCP — reachability, not policy.

This is a scoping decision, not a gap — do not add these as core features without explicit sign-off:

- **Encryption** (of the relay/hole-punched data path) is out of scope by design; confidentiality lives one layer up (the inner dialer's `tls`/`mtls`/`wss`). The transports are intentionally plaintext.
- **Peer discovery** (name→key) is an enhancement, not required — addressing is by base64 curve25519 public key, a complete scheme. See Roadmap for why it was abandoned.
- **A relay is inherent** to cross-NAT reachability; `derper` is a deployment choice (see `deploy/`), and symmetric-NAT peers stay on relay permanently.

An integrator supplies: a relay, peer public keys, and (if needed) its own encryption above the tunnel. Third-party embedders should start from [docs/embedding.md](docs/embedding.md).

## Build & Run

```bash
go build ./...              # all packages
go build -o p2p ./cmd/p2p   # the CLI (note: `go build ./cmd/p2p` writes nothing)
GOWORK=off go build ./...   # standalone build must also pass

# Run the stub (loopback bridge)
./p2p --addr 127.0.0.1:8003

# Run in DERP engine mode
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080
```

| Flag | Default | Meaning |
|---|---|---|
| `-C` | *(empty)* | config file (YAML); config values are defaults, explicitly-set flags override |
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--token` | *(empty)* | control-plane auth token; empty disables checking (loopback default) |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | inbound bridge target (repeatable; `"host:port"` = tcp, `"udp://host:port"` = udp; DERP mode) |
| `--forward` | *(empty)* | static port forward `"listen-addr=peer-key"` (repeatable; DERP mode) |
| `--stun` | *(empty)* | STUN server (host:port) for the IPv4 direct path; IPv6 direct works without STUN |
| `--direct` | `true` | attempt a direct (hole-punched) path; `false` forces relay-only (master switch) |
| `--tls.secure` | `true` | verify the relay's TLS certificate (`false` to trust any cert) |
| `--tls.caFile` | *(empty)* | PEM CA file to trust the relay's self-signed certificate |
| `--log.level` | `info` | log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `--log.format` | `json` | log format: `json` or `text` |
| `--log.output` | `stderr` | log output: `stderr`, `stdout`, `none`, or a file path (size-rotates at 100 MB) |

Every flag can instead live in a `-C config.yaml` ([cmd/p2p/config.go](cmd/p2p/config.go)); a config value
is the default and an explicitly-set flag overrides it. `--forward` and `--target`
flags are additive with their config lists (`forwards`, `targets`), so a config can
fully replace the command line. The YAML keys are unchanged from earlier versions:
the endpoint keys come from the inlined `p2p.Config`, `addr`/`token`/`log` are the
CLI's own.

## Architecture (two planes)

**Control plane** — the gRPC transport ([grpc/server.go](grpc/server.go), [grpc/rpc.go](grpc/rpc.go)) over an endpoint:

- `OpenTunnel(peer, network)` — authorizes a tunnel and replies `{ok, id}` with a cryptographically random id: it is the `Tunnel` stream's credential, so it must stay unguessable (never reuse the old guessable `tunnel-%d` scheme for it). `network` is `tcp` (a byte stream, the default) or `udp` (a datagram stream; requires DERP mode — a udp channel pairs two peers, not a host:port); anything else is `codes.InvalidArgument`. In stub mode `peer` must be `host:port` (validated); in DERP mode it must be a base64 32-byte public key. A record whose stream never arrives is reclaimed after ~10 s by a pending GC — the only cleanup for an abandoned setup.
- `Tunnel` — the data plane stream. The client presents the id from `OpenTunnel` as the `id` metadata key; the handler looks the record up (`codes.NotFound` if unknown/expired) and bridges the stream to the peer. Peer and target come from the record, never from the stream, so the client cannot spoof them. The stream's lifetime IS the tunnel's lifetime: the handler returning (client EOF/abort, peer EOF) drops the record. The host side of the stream is a raw byte pipe in every network mode.
- `Status` — tunnel count (pending records included) plus transport stats: gauges `direct_peers`/`derp_peers` (where each peer's traffic goes now) and cumulative counters `punch_attempts`/`punch_success`/`streams_direct`/`streams_derp`. The gauges probe each `directConn` with the side-effect-free `live()` — never `session()`, which tears a dead session down and schedules a re-punch, so a status query would churn connections. gRPC reflection is registered, so `grpcurl -plaintext <addr> proto.P2P/Status` works without shipping the proto (with `--token` set, add `-H 'token: …'`).

There is no `CloseTunnel`: the stream ending is the close.

**The seam** ([internal/host/seam.go](internal/host/seam.go)): `OpenTunnel` (validate + allocate a pending record) and `AttachTunnel(id, Stream, abort)` (claim, single use, then serve) are carrier-neutral — a transport that separates authorize from carry sits on them, while the in-process path dials and listens directly (`Host.Dial`/`Host.Listen`, which `endpoint.Endpoint` exposes). Validation, claim and peer-open failures return the root's sentinel errors (`ErrInvalidNetwork`, `ErrInvalidPeer`, `ErrUnknownTunnel`, `ErrTunnelAttached`, `ErrPeerUnreachable`) so a transport can map them without knowing the host.

**Embedder mode** (`endpoint.Listen` → `Host.Listen`): an in-process embedder can take inbound peer streams as
conns instead of letting the host bridge them to `--target` (mutually exclusive with
`Config.Targets`). Each accepted conn's `RemoteAddr()` carries the peer's base64 key, so the
embedder can route by peer, own the service stack (stats, auth, recording) and skip the target
pool entirely. `Dial` is the outbound counterpart; both are the same data plane the gRPC
carrier uses, only the stream carrier differs.

**Data plane** — the `Tunnel` stream per tunnel (see control plane). `--forward` listeners keep the old shape ([internal/host/server.go](internal/host/server.go) `bridge` → `pipe`): every accepted connection is bridged to the peer end and copied in both directions. Half-close semantics: when one direction EOFs, the destination gets `CloseWrite()` so the other side can drain — conn types without `CloseWrite` (mux and stream-backed conns) fall back to a full close; both ends close only after both directions finish. In DERP mode the peer end is an `engine.OpenStream(peer)` mux stream instead of a dialed TCP conn.

**DERP engine** ([internal/host/engine.go](internal/host/engine.go)): one long-lived WebSocket-DERP connection per host (client package `internal/derpclient`, a minimal DERP subset over the standard WS path — see its package doc for the wire reference @v1.102.3). A packet pump routes inbound packets to per-peer adapters; each peer pair has exactly one `smux` session (role chosen by public-key ordering) over which each tunnel is one stream. Both sides run an accept loop bridging inbound streams to `--target`. The host connects eagerly at startup (it is a rendezvous node) and redials every 5s on disconnect; `--key` is generated on first run and its public key printed — that base64 string is what peers put in their GOST node `addr`.

**Direct data plane** ([internal/host/direct.go](internal/host/direct.go)): on by default; `--direct=false` forces relay-only. After the relay smux session is up, each peer collects a candidate set — IPv4 via `--stun` (queried from the same UDP socket it will punch with) and IPv6 by binding the local egress address (`detectV6Egress`: a route lookup picks the source; IPv6 has no address translation, so the bound address is itself the reachable endpoint) — and exchanges sealed candidate frames over the relay control channel (`[0x00][kind]`, kind 0x02). The punch is **symmetric (mutual simultaneous open)**: both peers dial the peer's candidate with the same deterministic conv via `kcp.NewConn4(..., ownConn=true, socket)` (so session death closes the socket and the readLoop with no separate bookkeeping), then run `seedHandshake` — a symmetric echo where each peer must see its own token round-trip — so a half-open path can never yield a "false direct" session. smux runs over KCP with the same role-by-key-ordering as the relay (independent of who dialed). `OpenStream` prefers the direct smux session; on any failure it falls back to relay. The direct session is independent of the DERP transport (kept in a separate `e.directs` map) so it survives relay teardown — only `engine.Close` and the session's own death reclaim it. A failed punch (symmetric NAT) backoff-retries and traffic stays on relay. Package `internal/stun` is a minimal RFC 5389 binding client. Deployment-dependent timings (punch/seed/backoff/keepalive windows) are adjustable via the `timeouts:` config section — see `applyTimeouts` in [internal/host/apply.go](internal/host/apply.go); internal mechanism timeouts stay hardcoded. **These timings are process-wide** (one endpoint per process is the model). A peer answers an incoming candidate list with its own (de-duplicated), so a peer that started its punch late or reconnected to the relay converges in the same round instead of waiting out a timeout. Both peers independently prefer IPv6 when **both** candidate lists contain a v6 endpoint, else IPv4 (a pure function of the two lists, so the choice cannot disagree); a failed preferred family is retried on the other family in the same round before backing off. Capability negotiation rides along as a sealed bitfield (`ctrlCaps`, kind 0x04, re-sent with every candidate broadcast and ORed by the receiver) — a forward-looking seam that does **not** gate IPv6: the candidate list is the in-band signal.

**Datagram channel** (`network=udp`, [internal/host/udp.go](internal/host/udp.go)): a rendezvous between two *ends*, with a byte pump between the paired streams ([internal/host/udp.go](internal/host/udp.go) `serveStream`/`pumpLocal`). p2p special-cases neither end — which end a host holds is a deployment shape, not a mode:

- **end (1) — a local GOST udp `Tunnel` stream** (the per-peer `channel`, kept). `OpenTunnel(network=udp)` takes a reference (`record.ch`), the `Tunnel` stream becomes the channel's **local edge** (one per dial, last dial wins — a replaced edge is closed, ending that tunnel), and the **peer edge** is a persistent stream to the other host through the relay or the hole-punched path, opened by the smaller public key (`channel.loop`) and served by `acceptLoop` on the larger side, which routes tag-classified streams into the channel. This is the generic rendezvous a tun-to-tun link uses and a spoke dialling an outlet host uses. A channel stream is prefixed with the 4-byte magic `P2PU` so the responder can tell it apart from an ordinary tunnel stream; `peekTag` in [internal/host/udp.go](internal/host/udp.go) classifies each inbound stream **in its own goroutine** (so one silent stream cannot stall the accept loop) with a bounded read, and replays whatever a partial read consumed on the untagged path. The peer edge reconnects with backoff; the local edge survives its downtime. One channel per peer, reference-counted by open tunnels: the `Tunnel` handler's teardown (`dropTunnel`) is the only decrement, and the last one tears the channel down.
- **end (2) — a udp `--target` (a global datagram outlet).** The other end of a datagram link holds no channel: its `udp://…` target is a **global outlet** with **zero per-peer state**. Each inbound `P2PU`-tagged stream picks a target from the udp pool, dials it, and is bridged to it for the stream's lifetime ([internal/host/udp.go](internal/host/udp.go) `serveTargetStream`) — nothing outlives the stream. `serveInbound` resolves a tagged stream as **channel-first, else target**. Having no `channel.loop`, this end opens the peer edge only when it owns the smaller key and the peer's in-band udp-dial notice arrives (`ctrlDialUDP`, sealed — a malicious relay cannot forge it), via a per-peer opener loop ([internal/host/udp.go](internal/host/udp.go) `startDatagramDialer`/`datagramDialerLoop`, bounded by `maxDatagramDialers`); a host that holds a channel never also runs that loop (both would race over `setStream`, whose last-wins would livelock).

The host **never parses the data**: the GOST-side conn frames datagrams into 2-byte-prefixed frames and the peer's GOST-side conn parses them, so frame bytes travel through verbatim, both ways. Bytes are dropped while the opposite edge is absent or down (IP tolerates loss). GOST's `udp` dialer is the only user today: its tunnel carries a tun link end to end (the `play/p2p-tun.yaml` example in the gost repo) — GOST owns and configures the device, this host is only the pipe. The data path is unencrypted like the rest of the data plane.

**UDP target outlet** (a `udp://` target; [internal/host/udp.go](internal/host/udp.go) `serveTargetStream`): the *other* end of a datagram link — many NAT'd peers ("spokes") reach one NAT'd peer holding a single tun device (a GOST `tun` *server*). The outlet holds **no channel and no per-peer state**: each inbound `P2PU`-tagged stream dials a target from the udp pool and is bridged to it for that stream's lifetime, so nothing is prebuilt per key and `OpenTunnel(network=udp)` is not special-cased. The server's own per-IP route table then demultiplexes the spokes, so a spoke is a stock `tun` client with no host-side config. **There is no admission in p2p** — who may use the outlet is the caller's decision: the tun `auther`'s per-spoke passphrase, the relay's `-verify-clients=true`, or port binding/firewall. An unauthenticated `udp://` outlet is equivalent to exposing an unauthenticated tun server on the data plane. The outlet's tun handler must NOT set `tun.p2p` (that flag collapses the route table to a single peer). Because the source port changes whenever the peer edge is (re)established, the server's route (keyed by spoke IP) is refreshed by the tun client's next keepalive — that is the **tun application's** job, above p2p, not a p2p contract. This relies on the x-side keepalive fix in `x/handler/tun`: the client keepalive was gated on `network == "udp"`, so it was dead on a p2p link and routes never registered.

**Lifecycle**: non-mux inner (tcp/tls/ws): one tunnel per GOST dial; closing the tunnel conn ends the `Tunnel` stream, which drops the record (zero-residue verified in e2e). An `OpenTunnel` whose stream never arrives is reclaimed by the ~10 s pending GC. Mux inner (mtcp/mtls/mws): one tunnel per mux session, kept alive until the session dies or the process exits (gost's own mux semantics); N streams multiplex over it. In DERP mode the engine's smux session has the same shape one level down.

## Trust boundary (do not weaken)

By default the control channel is **unauthenticated**: anyone who can reach `--addr` can make this process dial arbitrary addresses (active-dial SSRF surface — unlike other plugin hosts, this one dials *out*). The **loopback default is the security boundary**. Streams are additionally authorized by the unguessable single-use id issued in `OpenTunnel` (looked up from the `Tunnel` stream's `id` metadata; the id is a secret — logs print only a short prefix). `--token <secret>` enables checking on every RPC via the gRPC `token` metadata key sent by the GOST client (constant-time compare; unary and stream RPCs alike — the stream check is defense in depth); the token travels over a plaintext channel today, so cross-machine deployment requires `--token` **plus** control TLS. In stub mode the peer string is forwarded to `net.DialTimeout` verbatim — keep the `SplitHostPort` validation in `OpenTunnel`; in DERP mode the peer is a public key and the bridge target is the host's own `--target`, so no peer-controlled dialing exists.

A DERP relay with `-verify-clients=false` is an **open relay**: it can observe and drop but not decrypt the bytes (no `DERPMeshKey`, no data-plane encryption at the relay). Confidentiality is the inner dialer's job (`mtls`/`tls`/`wss`).

The hole-punched KCP transport is likewise **unencrypted** (the `block` arg to `NewConn4` is nil): anyone on the UDP path can observe it. Candidate frames are sealed to the peer (`PrivateKey.SealTo`) so a malicious relay cannot forge them, but the data path carries no transport-layer crypto — same trust model as the relay, so do not weaken the inner dialer.

**A udp target outlet** shifts admission to the caller — p2p holds none. Who may reach the outlet's tun server is decided above: the tun `auther`'s per-spoke passphrase, the relay's `-verify-clients=true`, or port binding/firewall. The outlet is an **injection surface** — anything that can reach it can send datagrams into the tun server behind it, so an unauthenticated outlet is an unauthenticated tun server exposed on the data plane.

## Future milestones (in rough order)

1. ~~STUN + UDP hole-punched tunnels~~ — **shipped** (KCP + smux direct path, DERP relay as fallback).
2. (Not planned) Name→key discovery via DERP `PeerPresent` — **abandoned**: derper v1.102.3 only sends PeerPresent to mesh watchers, never to open-relay clients, so presence-driven discovery is infeasible. Peers are addressed by their base64 public key directly; any human-friendly name should be a static GOST config mapping, not a p2p-side registry.

(Muxed tunnels shipped in the mux milestone; DERP relay shipped in the derp milestone; hole punching shipped in the M2 milestone.)

## Verification

```bash
go build ./... && go vet ./...
GOWORK=off go build ./...              # module must build without go.work
gofmt -l .                             # must print nothing

# Tests, per package (a wildcard run is slow here; run them by package):
CGO_ENABLED=1 go test -race -count=1 ./...   # stun + direct + engine + derpclient + host + grpc + endpoint
```

The root package has a dependency test (`deps_test.go`): `go list -deps` on the
contracts must list nothing outside the standard library. It is the guard for the
promise third parties rely on — do not relax it to make an import compile.

E2E (`tests/e2e`, CLI + gRPC helper, see its README): official derper with
`-stun` (default on) + two p2p hosts + two gosts; curl through, then kill the
derper — traffic continues over the direct path. The relay-only path runs with
`-stun=false`.

The engine has in-process unit tests (`internal/host/engine_test.go`, a DERP-style relay in a test server); full relay semantics are verified against a real `derper` in e2e. The x-side contract tests (`x/p2p/plugin/grpc_test.go`) cover the GOST↔host seam.
