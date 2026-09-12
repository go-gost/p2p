# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## What this is

Standalone host process for the GOST [p2p plugin](https://github.com/go-gost/plugin) control protocol (`github.com/go-gost/plugin/p2p/proto`). GOST calls `OpenTunnel(peer)` over gRPC, then carries the tunnel's data on the `Tunnel` bidi stream bound to the returned id — no local endpoint is opened per tunnel (a firewall between GOST and this host used to block it). The GOST side (`x/p2p/`) uses that stream as the base connection of any whitelisted chain-node dialer.

Current implementation: **stub + mux + token + DERP relay + STUN/UDP hole punching + datagram channels**. It proves the plugin seam end to end, supports inner dialers `tcp/tls/ws/mtcp/mtls/mws/udp` (mux inners reuse one tunnel as a session; udp asks for a datagram stream instead of a byte stream — sidelined for now, see below), has optional control-plane token auth, and — with `--derp` — relays tunnels cross-machine through a DERP server. After a relay session is up, both peers punch a UDP hole (STUN + KCP + smux) and prefer the direct path; the relay stays as fallback. Data-plane encryption is end-to-end (the inner protocol's job). A udp tunnel is a **datagram channel**: one local UDP endpoint per peer, framed onto a persistent stream, which is what carries a tun link (GOST owns the device; this host is only the pipe). **Currently sidelined**: `OpenTunnel(network=udp)` answers `Unimplemented` until the channel's local edge moves onto the `Tunnel` stream (a local endpoint cannot cross a firewall); see Datagram channel below.

### Positioning / contract boundary

`p2p` is a **P2P connectivity layer, not a turnkey secure tunnel**. The contract is deliberately narrow: *give a peer public key, get a TCP tunnel; NAT traversal best-effort (STUN + hole punch, relay fallback); reachability is ours, security is the caller's.* This mirrors IP/TCP — reachability, not policy.

This is a scoping decision, not a gap — do not add these as core features without explicit sign-off:

- **Encryption** (of the relay/hole-punched data path) is out of scope by design; confidentiality lives one layer up (the inner dialer's `tls`/`mtls`/`wss`). The transports are intentionally plaintext.
- **Peer discovery** (name→key) is an enhancement, not required — addressing is by base64 curve25519 public key, a complete scheme. See Roadmap for why it was abandoned.
- **A relay is inherent** to cross-NAT reachability; `derper` is a deployment choice (see `deploy/`), and symmetric-NAT peers stay on relay permanently.

An integrator supplies: a relay, peer public keys, and (if needed) its own encryption above the tunnel.

## Build & Run

```bash
go build -o p2p .          # or: go run . (go.work resolves deps too)
GOWORK=off go build ./...  # standalone build must also pass

# Run the stub (loopback bridge)
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1

# Run in DERP engine mode
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080
```

| Flag | Default | Meaning |
|---|---|---|
| `-C` | *(empty)* | config file (YAML); config values are defaults, explicitly-set flags override |
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--bind` | `127.0.0.1` | **deprecated, no effect** (tunnels no longer open local endpoints); warns when explicitly set; removed with the udp rewrite |
| `--token` | *(empty)* | control-plane auth token; empty disables checking (loopback default) |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | local bridge target for inbound tunnels in DERP mode |
| `--forward` | *(empty)* | static port forward `"listen-addr=peer-key"` (repeatable; DERP mode) |
| `--stun` | *(empty)* | STUN server (host:port) for direct hole punching; empty disables direct (relay only) — opt-in |
| `--tls.secure` | `true` | verify the relay's TLS certificate (`false` to trust any cert) |
| `--tls.caFile` | *(empty)* | PEM CA file to trust the relay's self-signed certificate |
| `--log.level` | `info` | log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `--log.format` | `json` | log format: `json` or `text` |
| `--log.output` | `stderr` | log output: `stderr`, `stdout`, `none`, or a file path (size-rotates at 100 MB) |

Every flag can instead live in a `-C config.yaml` ([config.go](config.go)); a config value
is the default and an explicitly-set flag overrides it. `--forward` flags and the config
`forwards` list are additive, so a config can fully replace the command line.

## Architecture (two planes)

**Control plane** — gRPC service `P2P` ([server.go](server.go), [stream.go](stream.go)):

- `OpenTunnel(peer, network)` — authorizes a tunnel and replies `{ok, id}` with a cryptographically random id: it is the `Tunnel` stream's credential, so it must stay unguessable (never reuse the old guessable `tunnel-%d` scheme for it). `network` is `tcp` (a byte stream, the default); anything else is `codes.InvalidArgument`, except `udp`, which currently answers `codes.Unimplemented` (its data plane is deferred). In stub mode `peer` must be `host:port` (validated); in DERP mode it must be a base64 32-byte public key. A record whose stream never arrives is reclaimed after ~10 s by a pending GC — the only cleanup for an abandoned setup.
- `Tunnel` — the data plane stream. The client presents the id from `OpenTunnel` as the `id` metadata key; the handler looks the record up (`codes.NotFound` if unknown/expired) and bridges the stream to the peer. Peer and target come from the record, never from the stream, so the client cannot spoof them. The stream's lifetime IS the tunnel's lifetime: the handler returning (client EOF/abort, peer EOF) drops the record. The host side of the stream is a raw byte pipe in every network mode.
- `Status` — tunnel count (pending records included).

There is no `CloseTunnel`: the stream ending is the close.

**Data plane** — the `Tunnel` stream per tunnel (see control plane). `--forward` listeners keep the old shape ([server.go](server.go) `bridge` → `pipe`): every accepted connection is bridged to the peer end and copied in both directions. Half-close semantics: when one direction EOFs, the destination gets `CloseWrite()` so the other side can drain — conn types without `CloseWrite` (mux and stream-backed conns) fall back to a full close; both ends close only after both directions finish. In DERP mode the peer end is an `engine.OpenStream(peer)` mux stream instead of a dialed TCP conn.

**DERP engine** ([engine.go](engine.go)): one long-lived WebSocket-DERP connection per host (client package `internal/derpclient`, a minimal DERP subset over the standard WS path — see its package doc for the wire reference @v1.102.3). A packet pump routes inbound packets to per-peer adapters; each peer pair has exactly one `smux` session (role chosen by public-key ordering) over which each tunnel is one stream. Both sides run an accept loop bridging inbound streams to `--target`. The host connects eagerly at startup (it is a rendezvous node) and redials every 5s on disconnect; `--key` is generated on first run and its public key printed — that base64 string is what peers put in their GOST node `addr`.

**Direct data plane** ([direct.go](direct.go)): after the relay smux session is up, both peers query `--stun` from the same UDP socket they'll punch with, exchange sealed candidate frames over the relay control channel (`[0x00][kind]`, kind 0x02). The punch is **symmetric (mutual simultaneous open)**: both peers dial the peer's candidate with the same deterministic conv via `kcp.NewConn4(..., ownConn=true, socket)` (so session death closes the socket and the readLoop with no separate bookkeeping), then run `seedHandshake` — a symmetric echo where each peer must see its own token round-trip — so a half-open path can never yield a "false direct" session. smux runs over KCP with the same role-by-key-ordering as the relay (independent of who dialed). `OpenStream` prefers the direct smux session; on any failure it falls back to relay. The direct session is independent of the DERP transport (kept in a separate `e.directs` map) so it survives relay teardown — only `engine.Close` and the session's own death reclaim it. A failed punch (symmetric NAT) backoff-retries and traffic stays on relay. Package `internal/stun` is a minimal RFC 5389 binding client. Deployment-dependent timings (punch/seed/backoff/keepalive windows) are adjustable via the `timeouts:` config section — see `applyTimeouts` in [config.go](config.go); internal mechanism timeouts stay hardcoded. A peer answers an incoming candidate list with its own (de-duplicated), so a peer that started its punch late or reconnected to the relay converges in the same round instead of waiting out a timeout.

**Datagram channel** (`network=udp`, [udp.go](udp.go)) — **sidelined**: `OpenTunnel(network=udp)` answers `Unimplemented` until the channel's local edge moves onto the `Tunnel` stream (a local endpoint cannot cross a firewall, which is why this migration exists); the machinery below is retained for that rewrite. As built, it is the per-peer datagram tunnel — a UDP endpoint on `--bind` whose datagrams are framed ([frame.go](frame.go), 2-byte BE length prefix, one datagram per frame) onto a persistent stream, so packet boundaries survive the byte-stream data plane. Any datagram dialer's tunnel becomes one (GOST's `udp` dialer is the only user today): the local **gost dials the returned endpoint** and writes one IP packet per datagram, which is what carries a tun link — GOST owns and configures the device (the `play/p2p-tun.yaml` example in the gost repo), this host is only the pipe. One channel per peer, reference-counted by open tunnels: gost opens a tunnel per dial and closes it on reconnect, so the channel is torn down when the last one goes and rebuilt on the next open (a new endpoint port). Only the smaller public key opens the stream (`channel.loop`); the larger is served by `acceptLoop`. The endpoint learns its client from the packets it receives (gost announces itself with an empty datagram right after dialling) and last-writer-wins on a re-dial, so a peer that speaks first is still reachable; frames read before any client is known are dropped, as is everything while the stream is down (IP tolerates loss). A channel stream is prefixed with the 4-byte magic `P2PU` so the responder can tell it apart from an ordinary tunnel stream; `peekTag` in [udp.go](udp.go) classifies each inbound stream **in its own goroutine** (so one silent stream cannot stall the accept loop) with a bounded read, and replays whatever a partial read consumed on the untagged path. The data path is unencrypted like the rest of the data plane.

**Lifecycle**: non-mux inner (tcp/tls/ws): one tunnel per GOST dial; closing the tunnel conn ends the `Tunnel` stream, which drops the record (zero-residue verified in e2e). An `OpenTunnel` whose stream never arrives is reclaimed by the ~10 s pending GC. Mux inner (mtcp/mtls/mws): one tunnel per mux session, kept alive until the session dies or the process exits (gost's own mux semantics); N streams multiplex over it. In DERP mode the engine's smux session has the same shape one level down.

## Trust boundary (do not weaken)

By default the control channel is **unauthenticated**: anyone who can reach `--addr` can make this process dial arbitrary addresses (active-dial SSRF surface — unlike other plugin hosts, this one dials *out*). The **loopback default is the security boundary**. Streams are additionally authorized by the unguessable single-use id issued in `OpenTunnel` (looked up from the `Tunnel` stream's `id` metadata; the id is a secret — logs print only a short prefix). `--token <secret>` enables checking on every RPC via the gRPC `token` metadata key sent by the GOST client (constant-time compare; unary and stream RPCs alike — the stream check is defense in depth); the token travels over a plaintext channel today, so cross-machine deployment requires `--token` **plus** control TLS. In stub mode the peer string is forwarded to `net.DialTimeout` verbatim — keep the `SplitHostPort` validation in `OpenTunnel`; in DERP mode the peer is a public key and the bridge target is the host's own `--target`, so no peer-controlled dialing exists.

A DERP relay with `-verify-clients=false` is an **open relay**: it can observe and drop but not decrypt the bytes (no `DERPMeshKey`, no data-plane encryption at the relay). Confidentiality is the inner dialer's job (`mtls`/`tls`/`wss`).

The hole-punched KCP transport is likewise **unencrypted** (the `block` arg to `NewConn4` is nil): anyone on the UDP path can observe it. Candidate frames are sealed to the peer (`PrivateKey.SealTo`) so a malicious relay cannot forge them, but the data path carries no transport-layer crypto — same trust model as the relay, so do not weaken the inner dialer.

## Future milestones (in rough order)

1. ~~STUN + UDP hole-punched tunnels~~ — **shipped** (KCP + smux direct path, DERP relay as fallback).
2. (Not planned) Name→key discovery via DERP `PeerPresent` — **abandoned**: derper v1.102.3 only sends PeerPresent to mesh watchers, never to open-relay clients, so presence-driven discovery is infeasible. Peers are addressed by their base64 public key directly; any human-friendly name should be a static GOST config mapping, not a p2p-side registry.

(Muxed tunnels shipped in the mux milestone; DERP relay shipped in the derp milestone; hole punching shipped in the M2 milestone.)

## Verification

```bash
go build ./... && go vet ./...
GOWORK=off go build ./...   # module must build without go.work
CGO_ENABLED=1 go test -race ./...   # stun + direct + engine + derpclient unit tests

# E2E (see docs/2026-09-07-p2p-m2-holepunch.md): official derper with
# -stun (default on) + two p2p hosts + two gosts; curl through, then kill the
# derper — traffic continues over the direct path. The relay-only path runs
# with -stun=false.
```

The engine has in-process unit tests (`engine_test.go`, a DERP-style relay in a test server); full relay semantics are verified against a real `derper` in e2e. The x-side contract tests (`x/p2p/plugin/grpc_test.go`) cover the GOST↔host seam.
