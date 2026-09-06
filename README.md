# p2p

Tunnel host process for [GOST](https://github.com/go-gost/gost)'s [p2p plugin](https://github.com/go-gost/plugin) protocol. It lets GOST establish the network path to a chain node through a tunnel opened by this process — the traversal strategy (rendezvous, relay, hole punching) is entirely up to the plugin, and GOST only ever sees a plain local endpoint to dial.

**Status: stub + mux + DERP relay.** The host bridges tunnels with a local TCP forward, either directly (stub mode, loopback) or through a **DERP relay** (engine mode, cross-machine/NAT). Inner dialers `tcp/tls/ws/mtcp/mtls/mws` are supported — the mux family reuses one tunnel as a multiplexed session. Control-plane token auth is available (`--token`). No STUN/UDP hole punching yet — see the roadmap below.

## How it works

```
GOST client ──OpenTunnel(peer)──▶ p2p host (gRPC, :8003)
GOST client ◀─{id, endpoint}─────  p2p host
GOST client ──dial endpoint─────▶ p2p host ──bridge──▶ peer (host:port)
```

- `peer` is opaque: its semantics are defined by the plugin (a base64 public key in DERP mode, a plain `host:port` in stub mode).
- `endpoint` is opaque: v1 is a locally dialable TCP `host:port`. Closing the connection on the GOST side closes the tunnel.
- The GOST-side wiring (tunnel dialer, config) lives in `go-gost/x` (`x/p2p/`); the wire contract lives in `go-gost/plugin` (`p2p/proto`).

## Quick start

```bash
go build -o p2p .
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1 --debug
```

| Flag | Default | Meaning |
|---|---|---|
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--bind` | `127.0.0.1` | data-plane listen IP (one ephemeral port per tunnel) |
| `--token` | *(empty)* | control-plane auth token; empty disables checking |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | local bridge target for inbound tunnels in DERP mode |
| `--debug` | off | debug logging |

Point a GOST chain node at it:

```yaml
p2ps:
  - name: p2p-1
    plugin:
      type: grpc
      addr: 127.0.0.1:8003
      token: gost                       # matches the host's --token

chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: 192.168.1.10:8080   # the "peer" this stub bridges to
            connector:
              type: http              # connector follows the peer's protocol
            dialer:
              type: tcp
            metadata:
              p2p: p2p-1              # this node's base path goes through the plugin
```

## DERP mode (cross-machine)

The DERP engine relays tunnels through a [DERP server](https://tailscale.com/kb/1236) so peers behind NAT/firewalls can reach each other. The relay server is the official `derper` binary; this host speaks its WebSocket path (`Upgrade: websocket` + subprotocol `derp`), which is also what keeps it deployable behind Cloudflare and other WebSocket-capable proxies.

```bash
# relay server (self-hosted; auto-creates its key config on first run)
derper -c /etc/derper/derper.json -hostname derp.example.com -certmode manual -certdir /etc/derper/certs -a :443

# peer side — registers at the relay, bridges inbound tunnels to the local GOST
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080

# client side — serves the GOST control plane as usual
./p2p --derp wss://derp.example.com/derp --key client.key --addr 127.0.0.1:8003
```

Each host generates a curve25519 keypair on first run and prints its **public key** (base64) at startup. In DERP mode the GOST chain node's `addr` is the *peer host's public key*, not a `host:port` — see `go-gost/play/p2p-derp.yaml`. Everything else on the GOST side is unchanged.

## Security

The control channel is unauthenticated by default: any process that can reach `--addr` can make this host dial arbitrary addresses. Keep `--addr` on loopback (the default). For cross-machine deployment set `--token` (the GOST client sends it as gRPC metadata) **and** control TLS — the token alone travels over a plaintext gRPC channel today.

A DERP relay with `-verify-clients=false` is an open relay: it sees and can drop the bytes, but never decrypts them. Confidentiality is the inner protocol's job (use `mtls`/`tls`/`wss` inner dialers); the relay is transport, not trust.

## Roadmap

1. STUN + UDP hole-punched tunnels (needs a reliable-stream layer over UDP; DERP relay stays as fallback).
2. Rendezvous address discovery (DERP presence is available but not yet surfaced).

## License

MIT
