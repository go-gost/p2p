# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this directory.

## What this is

Standalone host process for the GOST [p2p plugin](https://github.com/go-gost/plugin) control protocol (`github.com/go-gost/plugin/p2p/proto`). GOST calls `OpenTunnel(peer)` over gRPC; this process returns a locally dialable TCP endpoint that bridges to the peer. The GOST side (`x/p2p/`) consumes the returned endpoint as the base connection of any whitelisted chain-node dialer.

Current implementation is the **stub milestone + mux/token**: it proves the plugin seam end to end, supports inner dialers `tcp/tls/ws/mtcp/mtls/mws` (mux inners reuse one tunnel as a session), and has optional control-plane token auth. No NAT traversal, rendezvous, DERP relay, hole punching, or data-plane encryption — those belong to future milestones of this repo.

## Build & Run

```bash
go build -o p2p .          # or: go run . (go.work resolves deps too)
GOWORK=off go build ./...  # standalone build must also pass

# Run the stub
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1 --debug
```

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--bind` | `127.0.0.1` | data-plane listen IP; each tunnel gets an ephemeral port on it |
| `--token` | *(empty)* | control-plane auth token; empty disables checking (loopback default) |
| `--debug` | off | slog debug level (tunnel open/close events) |

## Architecture (two planes)

**Control plane** — gRPC service `P2P` ([server.go](server.go)):

- `OpenTunnel(peer)` — validates peer is `host:port` (`codes.InvalidArgument` otherwise), opens a local TCP listener on `--bind`, registers `tunnel{id, ln, target}`, replies `{ok, id, endpoint}`. Business failures (listen error) answer `ok:false` with gRPC status OK; clients treat either channel as failure.
- `CloseTunnel(id)` — closes listener and all tracked connections. **Idempotent**: unknown id answers `ok:true`.
- `Status` — tunnel count.

**Data plane** — per tunnel ([server.go](server.go) `bridge`): every accepted connection is dialed to `target` (the peer) and copied in both directions. Half-close semantics: when one direction EOFs, the peer side gets `CloseWrite()` so the other side can drain; full close only after both directions finish.

**Lifecycle**: non-mux inner (tcp/tls/ws): one tunnel per GOST dial; `tunnelConn.Close()` triggers `CloseTunnel` (listener + connections), verified zero-residue in e2e. Mux inner (mtcp/mtls/mws): one tunnel per mux session, kept alive until the session dies or the process exits (gost's own mux semantics); N streams multiplex over it.

## Trust boundary (do not weaken)

By default the control channel is **unauthenticated**: anyone who can reach `--addr` can make this process dial arbitrary `host:port` (active-dial SSRF surface — unlike other plugin hosts, this one dials *out*). The **loopback default is the security boundary**. `--token <secret>` enables checking on every RPC via the gRPC `token` metadata key sent by the GOST client (constant-time compare); the token travels over a plaintext channel today, so cross-machine deployment requires `--token` **plus** control TLS. The peer string is forwarded to `net.DialTimeout` verbatim — keep the `SplitHostPort` validation in `OpenTunnel`.

## Future milestones (in rough order)

1. DERP-subset rendezvous/relay as an in-GOST service; this host grows the traversal engine.
2. UDP/hole-punched tunnels — **outside the current endpoint contract** (TCP-semantic byte pipe); needs a reliable-stream layer (QUIC/kcp class) and likely a new RPC family in the proto.

(Muxed tunnels — one tunnel = one port, many streams — shipped in the mux milestone.)

## Verification

```bash
go build ./... && go vet ./...
GOWORK=off go build ./...   # module must build without go.work

# E2E (see x/docs/plans/ p2p stub plan): gost peer + this stub +
# gost client with a p2ps:/metadata.p2p config, then curl through.
```

No tests in this repo yet; the x-side contract tests (`x/p2p/plugin/grpc_test.go`) and the e2e demo are the verification path.
