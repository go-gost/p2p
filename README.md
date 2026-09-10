# p2p

**English** · [简体中文](README.zh-CN.md)

Tunnel host process for [GOST](https://github.com/go-gost/gost)'s [p2p plugin](https://github.com/go-gost/plugin) protocol. It lets GOST establish the network path to a chain node through a tunnel opened by this process — the traversal strategy (rendezvous, relay, hole punching) is entirely up to the plugin, and GOST only ever sees a plain local endpoint to dial.

**Status: stub + mux + DERP relay + STUN/UDP hole punching + device link.** The host bridges tunnels with a local TCP forward, either directly (stub mode, loopback) or through a **DERP relay** (engine mode, cross-machine/NAT). In engine mode, after a relay session is up, both peers probe their NAT via STUN and punch a UDP hole; once the direct path (KCP + smux) is established, new tunnels flow over it while the relay stays up as fallback. Inner dialers `tcp/tls/ws/mtcp/mtls/mws` are supported — the mux family reuses one tunnel as a multiplexed session. Control-plane token auth is available (`--token`). A pre-existing tun/tap can also be bridged directly to the peer's same-kind device (`--link`, Linux) — a minimal point-to-point link.

## How it works

```
GOST client ──OpenTunnel(peer)──▶ p2p host (gRPC, :8003)
GOST client ◀─{id, endpoint}─────  p2p host
GOST client ──dial endpoint─────▶ p2p host ──bridge──▶ peer (host:port)
```

- `peer` is opaque: its semantics are defined by the plugin (a base64 public key in DERP mode, a plain `host:port` in stub mode).
- `endpoint` is opaque: v1 is a locally dialable TCP `host:port`. Closing the connection on the GOST side closes the tunnel.
- The GOST-side wiring (tunnel dialer, config) lives in `go-gost/x` (`x/p2p/`); the wire contract lives in `go-gost/plugin` (`p2p/proto`).

## Positioning: a generic P2P connectivity primitive

`p2p` is a **P2P connectivity layer, not a turnkey secure tunnel**. Its contract is deliberately narrow:

> Give me a peer public key, get back a TCP tunnel; NAT traversal is best-effort (STUN + UDP hole punching with a relay fallback); end-to-end reachability is this layer's job, security is the caller's.

It provides **reachability, not policy** — the same layering as IP/TCP:

- **Encryption is out of scope by design.** The relay and hole-punched transports carry plaintext (matching the relay's trust model: it can observe but never decrypt). Confidentiality belongs to the layer above — run `tls`/`mtls`/`wss` over the tunnel, exactly as the GOST inner dialers do. This is the standard connectivity/security layering, not a gap.
- **Peer discovery is an enhancement, not a requirement.** Peers are addressed by base64 curve25519 public key — a complete addressing scheme. Name→key lookup is intentionally not built in (see Roadmap).
- **A relay is inherent to NAT traversal.** Cross-NAT reachability without a rendezvous is impossible; `derper` is a deployment/infrastructure choice, not a design flaw. Symmetric-NAT peers stay on relay permanently.

**What an integrator must supply:** a relay (self-hosted `derper` or a third-party DERP), the public keys of the peers to reach, and — if confidentiality is required — its own encryption above the tunnel.

## Quick start

```bash
go build -o p2p .
./p2p --addr 127.0.0.1:8003 --bind 127.0.0.1
```

| Flag | Default | Meaning |
|---|---|---|
| `-C` | *(empty)* | config file (YAML); config values are defaults, explicitly-set flags override |
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--bind` | `127.0.0.1` | data-plane listen IP (one ephemeral port per tunnel) |
| `--token` | *(empty)* | control-plane auth token; empty disables checking |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | local bridge target for inbound tunnels in DERP mode |
| `--forward` | *(empty)* | static port forward `"listen-addr=peer-key"` (repeatable; DERP mode) |
| `--link` | *(empty)* | device link `"device=peer-key"` (`"p2p0=<key>"`, `"tap:veth0=<key>"`); DERP mode, Linux, exclusive with `--target`/`--forward`, single link |
| `--stun` | *(empty)* | STUN server (host:port) for direct hole punching; empty disables direct (relay only) — opt-in |
| `--tls.secure` | `true` | verify the relay's TLS certificate (`false` to trust any cert) |
| `--tls.caFile` | *(empty)* | PEM CA file to trust the relay's self-signed certificate |
| `--log.level` | `info` | log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `--log.format` | `json` | log format: `json` or `text` |
| `--log.output` | `stderr` | log output: `stderr`, `stdout`, `none`, or a file path (size-rotates at 100 MB) |

## Configuration file

Every flag can live in a YAML config file instead (gost-style `-C`): a config
value is the default, and an explicitly-set flag overrides it. `--forward`
flags and the config `forwards` list are additive (same for `--link` / `links`).

```bash
./p2p -C p2p.yaml
```

```yaml
addr: 127.0.0.1:8003
bind: 127.0.0.1
token: gost
derp: wss://derp.example.com/derp
key: peer.key
target: 127.0.0.1:18080
stun: stun.example.com:3478
tls:
  secure: false
  caFile: /etc/p2p/ca.pem
log:
  level: debug
  format: text
  output: /var/log/p2p.log
  rotation:
    maxSize: 50
    maxAge: 7
    maxBackups: 3
    localTime: true
    compress: true
forwards:
  - listen: 127.0.0.1:18080
    peer: <peerB-key>
# links:                            # device link (Linux); exclusive with target/forwards
#   - "p2p0=<peerB-key>"
```

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

The DERP engine relays tunnels through a [DERP server](https://tailscale.com/kb/1236) so peers behind NAT/firewalls can reach each other. The relay server is the official `derper` binary; this host speaks its WebSocket path (`Upgrade: websocket` + subprotocol `derp`), which is also what keeps it deployable behind Cloudflare and other WebSocket-capable proxies. **Note:** this WebSocket path is Tailscale's own browser-client transport (`cmd/tsconnect/wasm`, via `derpserver.AddWebSocketSupport`) — it is *not* described in the [custom DERP servers](https://tailscale.com/docs/reference/derp-servers/custom-derp-servers) docs, which only cover the native `Upgrade: DERP` hijack, so treat it as a de-facto rather than a documented API.

```bash
# relay server (self-hosted; auto-creates its key config on first run)
derper -c /etc/derper/derper.json -hostname derp.example.com -certmode manual -certdir /etc/derper/certs -a :443

# peer side — registers at the relay, bridges inbound tunnels to the local GOST
./p2p --derp wss://derp.example.com/derp --key peer.key --target 127.0.0.1:18080

# client side — serves the GOST control plane as usual
./p2p --derp wss://derp.example.com/derp --key client.key --addr 127.0.0.1:8003
```

Each host generates a curve25519 keypair on first run and prints its **public key** (base64) at startup. In DERP mode the GOST chain node's `addr` is the *peer host's public key*, not a `host:port`. Everything else on the GOST side is unchanged.

### Hole punching

When both peers are in engine mode, the relay is only used to establish the first session and carry the control channel. In the background each peer queries the derper's built-in STUN server (default port `3478`, `-stun` is on by default) to learn its public UDP endpoint, exchanges it with the peer over the relay, and builds a **KCP** session over the same UDP socket.

The punch is **symmetric**: both peers dial the peer's candidate with the same deterministic KCP conv (mutual simultaneous open), and a session is only used once **both** sides complete the echo handshake — each peer must see its own token round-trip, so a half-open path can never produce a "false direct" session. This removes the old "one side dials, the other accepts" asymmetry, which failed when only one direction could be punched (e.g. a peer inside a k3s pod whose inbound UDP needs the peer to have sent first).

On success new tunnels open streams over the direct smux session (KCP + smux); the relay session stays up so a direct-path failure silently falls back to relay and re-punches. The direct path keeps working even if the relay drops — only a *new* punch needs the relay back. A static `--forward` warms its peer's direct path at startup when `--stun` is set, so the first connection skips the punch latency.

Timings are tunable from the config file only (not flags); unset values keep the defaults, and invalid values fail at startup:

```yaml
timeouts:
  punchWait: 5s       # how long a stream waits for the direct path before relay
  punch: 10s          # whole-punch window (candidate wait + dial/seed)
  seed: 5s            # symmetric echo handshake window
  backoff: 30s        # retry interval after a failed punch
  derpKeepAlive: 30s  # DERP keepalive (keep below proxy idle timeouts)
  smux:
    interval: 10s
    timeout: 30s      # must be >= 2x interval
```

Symmetric NAT defeats UDP punching; those peers stay on relay permanently (periodic retry). The KCP transport is unencrypted, matching the relay's trust model — confidentiality is the inner dialer's job (`mtls`/`tls`/`wss`).

The derper's STUN server answers only Tailscale's binding-request dialect (`SOFTWARE` + `FINGERPRINT` attributes) and binds to the same IP as `-a`. Run derper with an explicit IP (`-a 1.2.3.4:443`) so STUN is reachable on the address family the peers will query; with a wildcard `-a :443` it binds IPv6-only, and the default IPv4 `--stun` (`derp host :3478`) won't reach it — set `--stun` explicitly in that case.

## Device link (tun/tap, Linux)

`--link "device=peer-key"` bridges a **pre-existing** local tun/tap directly to the peer's
same-kind device over one persistent stream — a minimal point-to-point link, and the
groundwork for tun-to-tun. Unlike `--forward`, no local listener is involved: each side
bridges its **own** device.

The p2p host **neither creates nor configures** the device — addresses, routes, MTU and
admin-up are yours — and the device must be **free**: a tun is exclusive-open, so it cannot
be shared with a process that already holds it (e.g. a gost tun listener). Only Linux is
supported.

In the container image this needs `--cap-add=NET_ADMIN --device /dev/net/tun` (and `--user 0`, since the default user is non-root); the image ships `iproute2` (for `ip tuntap`/`ip addr`/`ip link`) plus `iptables` and `nftables` for NAT/forwarding.

```bash
# on both ends, as root: create a persistent, unattached tun and configure it
ip tuntap add dev p2p0 mode tun
ip addr add 10.10.0.1/30 dev p2p0        # 10.10.0.2/30 on the other end
ip link set p2p0 up

./p2p --derp wss://derp.example.com/derp --key a.key --link "p2p0=<peerB-key>"
```

`tap` works the same with a `tap:` prefix (`--link "tap:veth0=<key>"`), forming an L2 link
(two nodes = a crossover cable; more than two is out of scope). The device is treated as an
opaque chunk device: every read becomes one length-prefixed frame, which preserves packet
boundaries for tun/tap and the byte stream for stream devices — so the two ends must be the
**same kind** (a stream source into a packet sink would scramble boundaries).

The link prefers the direct (hole-punched) path and falls back to the relay, exactly like a
tunnel. The opener — the host with the **smaller public key** — opens the stream; the other
side is served by its normal accept path. `--link` is mutually exclusive with
`--target`/`--forward`, only one link is supported, and the data path is **unencrypted**
like the rest of the data plane.

## Security

The control channel is unauthenticated by default: any process that can reach `--addr` can make this host dial arbitrary addresses. Keep `--addr` on loopback (the default). For cross-machine deployment set `--token` (the GOST client sends it as gRPC metadata) **and** control TLS — the token alone travels over a plaintext gRPC channel today.

A DERP relay with `-verify-clients=false` is an open relay: it sees and can drop the bytes, but never decrypts them. Confidentiality is the inner protocol's job (use `mtls`/`tls`/`wss` inner dialers); the relay is transport, not trust.

The **device link** is plaintext too: IP/Ethernet frames cross the relay or hole-punched path unencrypted, and unlike a tunnel there is no inner dialer to secure them. Run it only over a trusted path, or add your own encryption above it.

## Roadmap

1. ~~STUN + UDP hole-punched tunnels~~ — shipped (KCP + smux direct path, DERP relay as fallback).
2. Rendezvous address discovery — abandoned: derper v1.102.3 only sends `PeerPresent` to mesh watchers, never to open-relay clients, so presence-driven name discovery is infeasible. Peers are addressed by base64 public key; a human-friendly name belongs in the GOST config, not a p2p-side registry.
3. Device link (tun/tap over the tunnel) — shipped (`--link`, Linux): attach a pre-existing tun/tap and bridge it to the peer's same-kind device over a persistent direct-or-relay stream.

## License

MIT
