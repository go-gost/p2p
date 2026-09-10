# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## What this is

Standalone host process for the GOST [p2p plugin](https://github.com/go-gost/plugin) control protocol (`github.com/go-gost/plugin/p2p/proto`). GOST calls `OpenTunnel(peer)` over gRPC; this process returns a locally dialable TCP endpoint that bridges to the peer. The GOST side (`x/p2p/`) consumes the returned endpoint as the base connection of any whitelisted chain-node dialer.

Current implementation: **stub + mux + token + DERP relay + STUN/UDP hole punching**. It proves the plugin seam end to end, supports inner dialers `tcp/tls/ws/mtcp/mtls/mws` (mux inners reuse one tunnel as a session), has optional control-plane token auth, and — with `--derp` — relays tunnels cross-machine through a DERP server. After a relay session is up, both peers punch a UDP hole (STUN + KCP + smux) and prefer the direct path; the relay stays as fallback. Data-plane encryption is end-to-end (the inner protocol's job).

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
| `--bind` | `127.0.0.1` | data-plane listen IP; each tunnel gets an ephemeral port on it |
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

**Control plane** — gRPC service `P2P` ([server.go](server.go)):

- `OpenTunnel(peer)` — opens a local TCP listener on `--bind` and replies `{ok, id, endpoint}`. In stub mode `peer` must be `host:port` (validated, `codes.InvalidArgument` otherwise); in DERP mode `peer` must be a base64 32-byte public key. Business failures (listen error) answer `ok:false` with gRPC status OK; clients treat either channel as failure.
- `CloseTunnel(id)` — closes listener and all tracked connections. **Idempotent**: unknown id answers `ok:true`.
- `Status` — tunnel count.

**Data plane** — per tunnel ([server.go](server.go) `bridge`): every accepted connection is bridged to the target and copied in both directions. Half-close semantics: when one direction EOFs, the peer side gets `CloseWrite()` so the other side can drain; full close only after both directions finish. In DERP mode the target is an `engine.OpenStream(peer)` mux stream instead of a dialed TCP conn.

**DERP engine** ([engine.go](engine.go)): one long-lived WebSocket-DERP connection per host (client package `internal/derpclient`, a minimal DERP subset over the standard WS path — see its package doc for the wire reference @v1.102.3). A packet pump routes inbound packets to per-peer adapters; each peer pair has exactly one `smux` session (role chosen by public-key ordering) over which each tunnel is one stream. Both sides run an accept loop bridging inbound streams to `--target`. The host connects eagerly at startup (it is a rendezvous node) and redials every 5s on disconnect; `--key` is generated on first run and its public key printed — that base64 string is what peers put in their GOST node `addr`.

**Direct data plane** ([direct.go](direct.go)): after the relay smux session is up, both peers query `--stun` from the same UDP socket they'll punch with, exchange sealed candidate frames over the relay control channel (`[0x00][kind]`, kind 0x02). The punch is **symmetric (mutual simultaneous open)**: both peers dial the peer's candidate with the same deterministic conv via `kcp.NewConn4(..., ownConn=true, socket)` (so session death closes the socket and the readLoop with no separate bookkeeping), then run `seedHandshake` — a symmetric echo where each peer must see its own token round-trip — so a half-open path can never yield a "false direct" session. smux runs over KCP with the same role-by-key-ordering as the relay (independent of who dialed). `OpenStream` prefers the direct smux session; on any failure it falls back to relay. The direct session is independent of the DERP transport (kept in a separate `e.directs` map) so it survives relay teardown — only `engine.Close` and the session's own death reclaim it. A failed punch (symmetric NAT) backoff-retries and traffic stays on relay. Package `internal/stun` is a minimal RFC 5389 binding client. Deployment-dependent timings (punch/seed/backoff/keepalive windows) are adjustable via the `timeouts:` config section — see `applyTimeouts` in [config.go](config.go); internal mechanism timeouts stay hardcoded. A peer answers an incoming candidate list with its own (de-duplicated), so a peer that started its punch late or reconnected to the relay converges in the same round instead of waiting out a timeout.

**Lifecycle**: non-mux inner (tcp/tls/ws): one tunnel per GOST dial; `tunnelConn.Close()` triggers `CloseTunnel` (listener + connections), verified zero-residue in e2e. Mux inner (mtcp/mtls/mws): one tunnel per mux session, kept alive until the session dies or the process exits (gost's own mux semantics); N streams multiplex over it. In DERP mode the engine's smux session has the same shape one level down.

## Trust boundary (do not weaken)

By default the control channel is **unauthenticated**: anyone who can reach `--addr` can make this process dial arbitrary addresses (active-dial SSRF surface — unlike other plugin hosts, this one dials *out*). The **loopback default is the security boundary**. `--token <secret>` enables checking on every RPC via the gRPC `token` metadata key sent by the GOST client (constant-time compare); the token travels over a plaintext channel today, so cross-machine deployment requires `--token` **plus** control TLS. In stub mode the peer string is forwarded to `net.DialTimeout` verbatim — keep the `SplitHostPort` validation in `OpenTunnel`; in DERP mode the peer is a public key and the bridge target is the host's own `--target`, so no peer-controlled dialing exists.

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
