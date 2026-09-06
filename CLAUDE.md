# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## What this is

Standalone host process for the GOST [p2p plugin](https://github.com/go-gost/plugin) control protocol (`github.com/go-gost/plugin/p2p/proto`). GOST calls `OpenTunnel(peer)` over gRPC; this process returns a locally dialable TCP endpoint that bridges to the peer. The GOST side (`x/p2p/`) consumes the returned endpoint as the base connection of any whitelisted chain-node dialer.

Current implementation: **stub + mux + token + DERP relay + name discovery**. It proves the plugin seam end to end, supports inner dialers `tcp/tls/ws/mtcp/mtls/mws` (mux inners reuse one tunnel as a session), has optional control-plane token auth, and — with `--derp` — relays tunnels cross-machine through a DERP server where hosts can announce service names so peers dial by name. Data-plane encryption is end-to-end (the inner protocol's job); STUN/UDP hole punching is a future milestone.

## Build & Run

```bash
go build -o p2p .          # or: go run . (go.work resolves deps too)
GOWORK=off go build ./...  # standalone build must also pass

# Run the stub (loopback bridge)
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1 --debug

# Run in DERP engine mode
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080
```

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--bind` | `127.0.0.1` | data-plane listen IP; each tunnel gets an ephemeral port on it |
| `--token` | *(empty)* | control-plane auth token; empty disables checking (loopback default) |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | local bridge target for inbound tunnels in DERP mode |
| `--service` | *(none)* | service name to announce (repeatable); peer dials by name instead of base64 key |
| `--debug` | off | slog debug level (tunnel open/close events) |

## Architecture (two planes)

**Control plane** — gRPC service `P2P` ([server.go](server.go)):

- `OpenTunnel(peer)` — opens a local TCP listener on `--bind` and replies `{ok, id, endpoint}`. In stub mode `peer` must be `host:port` (validated, `codes.InvalidArgument` otherwise); in DERP mode `peer` must be a base64 32-byte public key. Business failures (listen error) answer `ok:false` with gRPC status OK; clients treat either channel as failure.
- `CloseTunnel(id)` — closes listener and all tracked connections. **Idempotent**: unknown id answers `ok:true`.
- `Status` — tunnel count.

**Data plane** — per tunnel ([server.go](server.go) `bridge`): every accepted connection is bridged to the target and copied in both directions. Half-close semantics: when one direction EOFs, the peer side gets `CloseWrite()` so the other side can drain; full close only after both directions finish. In DERP mode the target is an `engine.OpenStream(peer)` mux stream instead of a dialed TCP conn.

**DERP engine** ([engine.go](engine.go)): one long-lived WebSocket-DERP connection per host (client package `internal/derpclient`, a minimal DERP subset over the standard WS path — see its package doc for the wire reference @v1.102.3). A packet pump routes inbound packets to per-peer adapters; each peer pair has exactly one `smux` session (role chosen by public-key ordering) over which each tunnel is one stream. Both sides run an accept loop bridging inbound streams to `--target`. The host connects eagerly at startup (it is a rendezvous node) and redials every 5s on disconnect; `--key` is generated on first run and its public key printed — that base64 string is what peers put in their GOST node `addr`.

**Name discovery** ([engine.go](engine.go) `Lookup`/`announceOn`, [server.go](server.go) at `OpenTunnel`): above the DERP packet stream the engine puts a 1-byte application-frame type — `0x01` session data (the smux bytes, tagged on write and stripped once by the pump), `0x00` control frames whose `kind 0x01` is a name announcement carrying the announcing peer's key from the DERP packet source (host identity is never repeated in the frame). `derpclient` surfaces `PeerPresent`/`PeerGone` on a per-connection `Presence()` channel; the engine tracks the `online` set, announces its `--service` names to a newly-present peer immediately and every 15s thereafter, and caches `name → key` (newest wins, evicted on `PeerGone`, 60s TTL backstop). `OpenTunnel` in DERP mode tries the base64-key parse first (keys win by protocol precedence — a name can never be ambiguous with a key for the addresser) and falls back to name resolution, returning `NotFound` for unknown names. `-F p2p://<key>` keeps working unchanged.

**Lifecycle**: non-mux inner (tcp/tls/ws): one tunnel per GOST dial; `tunnelConn.Close()` triggers `CloseTunnel` (listener + connections), verified zero-residue in e2e. Mux inner (mtcp/mtls/mws): one tunnel per mux session, kept alive until the session dies or the process exits (gost's own mux semantics); N streams multiplex over it. In DERP mode the engine's smux session has the same shape one level down.

## Trust boundary (do not weaken)

By default the control channel is **unauthenticated**: anyone who can reach `--addr` can make this process dial arbitrary addresses (active-dial SSRF surface — unlike other plugin hosts, this one dials *out*). The **loopback default is the security boundary**. `--token <secret>` enables checking on every RPC via the gRPC `token` metadata key sent by the GOST client (constant-time compare); the token travels over a plaintext channel today, so cross-machine deployment requires `--token` **plus** control TLS. In stub mode the peer string is forwarded to `net.DialTimeout` verbatim — keep the `SplitHostPort` validation in `OpenTunnel`; in DERP mode the peer is a public key and the bridge target is the host's own `--target`, so no peer-controlled dialing exists.

A DERP relay with `-verify-clients=false` is an **open relay**: it can observe and drop but not decrypt the bytes (no `DERPMeshKey`, no data-plane encryption at the relay). Confidentiality is the inner dialer's job (`mtls`/`tls`/`wss`).

## Future milestones (in rough order)

1. STUN + UDP hole-punched tunnels — needs a reliable-stream layer over UDP; the DERP engine stays as the fallback relay.
2. ✅ Name discovery over DERP presence (`PeerPresent` surfaced; shipped in the discovery milestone).

(Muxed tunnels shipped in the mux milestone; DERP relay shipped in the derp milestone.)

## Verification

```bash
go build ./... && go vet ./...
GOWORK=off go build ./...   # module must build without go.work
CGO_ENABLED=1 go test -race ./...   # derpclient + engine unit tests

# E2E (see x/docs/plans/2026-09-06-p2p-derp-relay.md): official derper +
# two p2p hosts + two gosts, curl through; plus the stub-mode matrix.
```

The engine has in-process unit tests (`engine_test.go`, a DERP-style relay in a test server); full relay semantics are verified against a real `derper` in e2e. The x-side contract tests (`x/p2p/plugin/grpc_test.go`) cover the GOST↔host seam.
