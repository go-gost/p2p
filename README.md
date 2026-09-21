# p2p

**English** · [简体中文](README.zh-CN.md)

Tunnel host process for [GOST](https://github.com/go-gost/gost)'s [p2p plugin](https://github.com/go-gost/plugin) protocol. It lets GOST establish the network path to a chain node through a tunnel opened by this process — the traversal strategy (rendezvous, relay, hole punching) is entirely up to the plugin, and GOST only ever sees a plain byte stream (the `Tunnel` gRPC stream) to carry its protocol over.

**Status: stub + mux + DERP relay + STUN/UDP hole punching + datagram channels.** The host bridges tunnels with a local TCP forward, either directly (stub mode, loopback) or through a **DERP relay** (engine mode, cross-machine/NAT). In engine mode, after a relay session is up, both peers probe their NAT via STUN and punch a UDP hole; once the direct path (KCP + smux) is established, new tunnels flow over it while the relay stays up as fallback. Inner dialers `tcp/tls/ws/mtcp/mtls/mws/udp` are supported — the mux family reuses one tunnel as a multiplexed session, and `udp` asks for a **datagram stream** instead of a byte stream (this is what carries a tun link: GOST owns the device, this host is only the pipe).

## How it works

```
GOST client ──OpenTunnel(peer, network)──▶ p2p host (gRPC, :8003)
GOST client ◀──{ok, id}────────────────────  p2p host
GOST client ══Tunnel stream ("id" key)════▶ p2p host ──bridge──▶ peer
```

- `peer` is opaque: its semantics are defined by the plugin (a base64 public key in DERP mode, a plain `host:port` in stub mode).
- `OpenTunnel` only authorizes the tunnel and returns a cryptographically random, single-use `id`. The **data rides the `Tunnel` gRPC stream** bound to that id (sent as the `id` metadata key) — there is no local endpoint to dial, so a firewall between GOST and this host can't block the data path. Closing the stream closes the tunnel; the stream's lifetime *is* the tunnel's lifetime.
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
go build -o p2p ./cmd/p2p
./p2p --addr 127.0.0.1:8003
```

| Flag | Default | Meaning |
|---|---|---|
| `-C` | *(empty)* | config file (YAML); config values are defaults, explicitly-set flags override |
| `--addr` | `127.0.0.1:8003` | gRPC control-plane listen address |
| `--token` | *(empty)* | control-plane auth token; empty disables checking |
| `--derp` | *(empty)* | DERP relay URL (`wss://host/derp`); enables engine mode |
| `--key` | `$XDG_CONFIG_HOME/p2p/key-v1` | curve25519 private key file (hex); created if missing |
| `--target` | *(empty)* | inbound bridge target (repeatable; bare `"host:port"` feeds the tcp pool, `"udp://host:port"` the udp pool; DERP mode) |
| `--forward` | *(empty)* | static port forward `"listen-addr=peer-key"` (repeatable; DERP mode) |
| `--stun` | *(empty)* | STUN server (host:port) for the IPv4 direct path; IPv6 direct works without STUN |
| `--direct` | `true` | attempt a direct (hole-punched) path; `false` forces relay-only |
| `--tls.secure` | `true` | verify the relay's TLS certificate (`false` to trust any cert) |
| `--tls.caFile` | *(empty)* | PEM CA file to trust the relay's self-signed certificate |
| `--log.level` | `info` | log level: `trace`, `debug`, `info`, `warn`, `error`, `fatal` |
| `--log.format` | `json` | log format: `json` or `text` |
| `--log.output` | `stderr` | log output: `stderr`, `stdout`, `none`, or a file path (size-rotates at 100 MB) |

## Configuration file

Every flag can live in a YAML config file instead (gost-style `-C`): a config
value is the default, and an explicitly-set flag overrides it. `--forward`
flags and the config `forwards` list are additive.

```bash
./p2p -C p2p.yaml
```

```yaml
addr: 127.0.0.1:8003
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

### DERP wire frames

The relay link is a WebSocket carrying DERP binary frames. Two layers are worth knowing: the DERP protocol itself (shared with every Tailscale client) and the small p2p framing this host puts *inside* a relayed packet.

**DERP frame** — `[type 1B][length 4B big-endian][body]`, from `tailscale.com/derp@v1.102.3`:

| Type | Name | Body |
|---|---|---|
| `0x01` | ServerKey | 8-byte magic (`DERP` + key emoji) + 32-byte server public key |
| `0x02` | ClientInfo | 32-byte client pubkey + 24-byte nonce + NaCl-box(JSON `{Version, CanAckPings}`) to the server key |
| `0x03` | ServerInfo | 24-byte nonce + NaCl-box(JSON); token-bucket hints, advisory |
| `0x04` | SendPacket | 32-byte destination pubkey + packet bytes (≤ 64 KiB) |
| `0x05` | RecvPacket | v2: 32-byte **source** pubkey + packet bytes |
| `0x06` | KeepAlive | none — no-op |
| `0x08` | PeerGone | 32-byte pubkey + 1-byte reason (informational) |
| `0x09` | PeerPresent | 32-byte pubkey (informational; derper only sends it to mesh watchers) |
| `0x12` / `0x13` | Ping / Pong | 8-byte payload; `Recv` echoes a Ping back as Pong |

Handshake: the server greets with `ServerKey`, the client replies `ClientInfo` (boxed to the server key, proving possession of its private key), the server answers `ServerInfo`. Everything else is `SendPacket`/`RecvPacket`. **Unknown frame types are skipped** (the reference client's `recv` switch has no default case) — the same forward-compat rule applies here. The client is addressed purely by its 32-byte public key; the base64 form is that key.

**p2p packet framing** — the bytes inside every `SendPacket`/`RecvPacket` start with a type byte:

| Byte | Meaning |
|---|---|
| `0x00` | control frame: `[0x00][kind 1B][NaCl-boxed payload]` |
| `0x01` | data frame: `[0x01][smux byte stream]` — one DERP packet per smux write |

Control kinds: `0x02` punch candidates (sealed `[count]([family][addr][port])*`), `0x03` udp-tunnel dial notice (sealed, empty), `0x04` capability bitfield (sealed 1 byte; bit 0 = IPv6-aware, re-sent with each broadcast and OR'd by the receiver). All control payloads are sealed to the peer key (`PrivateKey.SealTo`), so the relay can route but not forge them. Control frames are consumed by the engine; data frames feed the per-peer smux session.

### Hole punching

When both peers are in engine mode, the relay is only used to establish the first session and carry the control channel. In the background each peer queries the derper's built-in STUN server (default port `3478`, `-stun` is on by default) to learn its public UDP endpoint, exchanges it with the peer over the relay, and builds a **KCP** session over the same UDP socket.

The punch is **symmetric**: both peers dial the peer's candidate with the same deterministic KCP conv (mutual simultaneous open), and a session is only used once **both** sides complete the echo handshake — each peer must see its own token round-trip, so a half-open path can never produce a "false direct" session. This removes the old "one side dials, the other accepts" asymmetry, which failed when only one direction could be punched (e.g. a peer inside a k3s pod whose inbound UDP needs the peer to have sent first).

On success new tunnels open streams over the direct smux session (KCP + smux); the relay session stays up so a direct-path failure silently falls back to relay and re-punches. The direct path keeps working even if the relay drops — only a *new* punch needs the relay back. A static `--forward` warms its peer's direct path at startup when `--stun` is set, so the first connection skips the punch latency. Direct is on by default (`--direct=false` forces relay-only). IPv6 is a first-class candidate family: a host with a global IPv6 egress binds and advertises that address (no STUN, no NAT), and both peers prefer IPv6 when both offer it, retrying IPv4 in the same round if the v6 path does not complete.

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

## Datagram channels (a tun link, Linux)

A chain node whose dialer is `udp` asks for a **datagram stream** (`network=udp`) instead of
a byte stream. The `Tunnel` stream carries it like any other tunnel; on each side this host
pairs the persistent per-peer edge (the direct-or-relay stream to the other host) with the
latest gost tunnel's stream and pumps bytes between them. The GOST-side conn frames each
datagram into a length-prefixed frame and the peer's GOST-side conn parses it, so packet
boundaries survive the byte-stream data plane and **this host never parses the data**. That
is what makes a tun-to-tun link possible — **GOST owns the device** (the `tun` listener
creates and configures it, the `tun` handler bridges it), this host is only the pipe. A tun
device is exclusive-open, so the device cannot be shared: GOST having its own tun stack is
the whole point.

```bash
# both ends: no --target, no device flags. The peer's key goes in the GOST node addr.
./p2p --derp wss://derp.example.com/derp --key a.key --addr 127.0.0.1:8003 --stun derp.example.com:3478
```

```yaml
# GOST side (each end; see play/p2p-tun.yaml in the gost repo)
p2ps:
  - name: p2p-1
    plugin: {type: grpc, addr: 127.0.0.1:8003}
services:
  - name: tun-0
    addr: :0                      # the tun listener binds no socket
    handler: {type: tun, chain: chain-0}      # chain without forwarder = client mode
    listener:
      type: tun
      metadata: {name: p2p0, net: 10.10.0.1/30, mtu: 1420}   # 10.10.0.2/30 on the peer
chains:
  - name: chain-0
    hops:
      - name: hop-0
        nodes:
          - name: node-0
            addr: <peerB-key>     # in p2p mode the addr IS the peer key
            dialer: {type: udp}   # datagram semantics
            connector: {type: forward}   # transparent (the default is http)
            metadata: {p2p: p2p-1}
```

One channel exists per peer, shared by every tunnel to it and reference-counted: GOST opens
a tunnel per dial and closes it on reconnect, so the channel is torn down when the last one
closes and rebuilt on the next open. Only the host with the **smaller public key** opens
the peer edge's stream; the other side is served by its normal accept path. A re-dial takes
over the local edge (last dial wins), and the peer edge reconnects with backoff across its
own downtime while the local edge persists. The link prefers the direct (hole-punched) path
and falls back to the relay, exactly like a tunnel. `network=udp` requires engine mode
(`--derp`): a channel is addressed by peer key.

Bytes are dropped whenever one side has no live edge yet (IP tolerates loss), so a side
that has nothing to send yet is still reachable. The data path is **unencrypted** like the
rest of the data plane: there is no inner dialer here to secure it, so run it over a trusted
path or add your own encryption above it.

## UDP target (a global datagram outlet)

A `udp://` `--target` is a **global datagram outlet** — a datagram channel's second kind of
*end*, and unlike the per-peer channel it is **not bound to any peer**. Every inbound datagram
stream (a stream prefixed with the `P2PU` tag) picks a target from the udp pool, dials it, and
is bridged to it for the stream's lifetime: the stream's frames become raw IP datagrams at the
outlet, and each datagram comes back framed on the stream. The outlet side keeps **zero
per-peer state** — no prebuilt channel, no per-key socket, nothing that outlives a single
stream. This is the shape a `tun` *server* behind NAT wants: many NAT'd `tun` clients reach one
NAT'd peer that holds a single tun device.

```bash
# outlet side: p2p with a udp target pointing at the tun server — no --allow, no per-peer config
./p2p --derp wss://derp.example.com/derp --key outlet.key \
      --target udp://127.0.0.1:8421 --stun derp.example.com:3478

# outlet side: GOST tun SERVER — do NOT set tun.p2p (that flag is the single-peer mode)
#   gost -L "tun://127.0.0.1:8421?net=10.10.0.1/24&keepalive=true&ttl=10s&token=<passphrase>"
#   auther: user = each spoke's tun IP, password = the shared passphrase
#   sysctl -w net.ipv4.ip_forward=1     # to reach a network behind the outlet
```

The spoke is a stock `tun` client: `net 10.10.0.<n>/24`, `keepalive: true`, the same `token`,
and a `route` for whatever lies behind the outlet; its chain node addr is the **outlet host's
key** with `dialer: udp` / `connector: forward`, exactly like the point-to-point link.

- **Two ends, one rendezvous.** A datagram channel pairs two *ends*, and p2p special-cases
  neither. End (1) is a local GOST udp `Tunnel` stream — the per-peer `channel` above, the
  generic rendezvous a tun-to-tun link uses and a spoke dialling an outlet also uses. End (2)
  is a udp `--target` — this global outlet. Which end a host holds is a deployment shape, not
  a mode. The opener is decided by public-key order (the smaller key opens): the channel side
  opens through its own loop, while the outlet side — which has no channel — opens when the
  peer's in-band udp-dial notice arrives; a host that holds a channel never runs that loop too.
- **Admission is the caller's, not p2p's.** Who may use the outlet is decided above this
  layer: the tun `auther`'s per-spoke passphrase, the relay's `-verify-clients=true`, or
  simply port binding/firewall. **An unauthenticated `udp://` outlet is equivalent to exposing
  an unauthenticated tun server on the data plane** — put the tun handler's `token`/passphrase
  (or an equivalent) in front of it.
- **`keepalive` is the tun app's job, above p2p.** The outlet's source port changes whenever
  the peer edge is (re)established, so the tun server's route (keyed by spoke IP) is refreshed
  by the tun client's next keepalive — the tun application's responsibility, not a p2p
  contract. A tun client that never sends keepalive will, after its first reconnect, have the
  server's downstream pointed at a dead port. Set `keepalive` on the spokes (their peer is the
  tun server, which echoes and registers their route); the server-side `keepalive/ttl` also
  expires an absent spoke's route instead of black-holing.

`--target` is repeatable and feeds two pools: a bare `host:port` is a **tcp** target (inbound
byte-stream tunnels), `udp://host:port` is a **udp** target (the outlet above). Multiple udp
targets round-robin inbound datagram streams across outlets.

## Transport stats

The host reports its direct/relay statistics over the existing gRPC `Status`
RPC, so you can tell whether hole punching actually works for your peers:

```bash
grpcurl -plaintext 127.0.0.1:8003 proto.P2P/Status
```

```json
{
  "tunnels": 4,
  "directPeers": 12, "derpPeers": 3,
  "punchAttempts": 45, "punchSuccess": 15,
  "streamsDirect": 210, "streamsDerp": 30
}
```

`directPeers`/`derpPeers` are gauges — where each peer's traffic goes *right
now*; `punch*` and `streams*` are cumulative since start. A `punchAttempts`
that climbs while `punchSuccess` stays flat means hole punching is being tried
and failing (symmetric NAT / CGNAT) — the case IPv6 or port mapping would
address. With `--token` set, add `-H 'token: <token>'`.

## Security

The control channel is unauthenticated by default: any process that can reach `--addr` can make this host dial arbitrary addresses. Keep `--addr` on loopback (the default). For cross-machine deployment set `--token` (the GOST client sends it as gRPC metadata) **and** control TLS — the token alone travels over a plaintext gRPC channel today.

A DERP relay with `-verify-clients=false` is an open relay: it sees and can drop the bytes, but never decrypts them. Confidentiality is the inner protocol's job (use `mtls`/`tls`/`wss` inner dialers); the relay is transport, not trust.

A **datagram channel** is plaintext too: IP packets cross the relay or hole-punched path unencrypted, and unlike a tunnel dialer there is nothing above them in this host to secure them. Run it only over a trusted path, or add your own encryption above the link (GOST's `tls`/`mtls` dialers do not apply to a `udp` tunnel).

**A udp outlet** shifts admission to the caller: p2p holds none. Who may reach the outlet's tun
server is decided above — the tun `auther`'s per-spoke passphrase, the relay's
`-verify-clients=true`, or port binding/firewall. An outlet with nothing in front of it is an
unauthenticated tun server exposed on the data plane.

## Roadmap

1. ~~STUN + UDP hole-punched tunnels~~ — shipped (KCP + smux direct path, DERP relay as fallback).
2. Rendezvous address discovery — abandoned: derper v1.102.3 only sends `PeerPresent` to mesh watchers, never to open-relay clients, so presence-driven name discovery is infeasible. Peers are addressed by base64 public key; a human-friendly name belongs in the GOST config, not a p2p-side registry.
3. Datagram channels (tun/tap over the tunnel) — shipped (`network=udp`): a per-peer byte pipe between the peer's stream and the latest gost tunnel's stream, carried inside the same `Tunnel` streams. The device itself is GOST's (the `tun` listener/handler), this host is only the pipe.
4. UDP target outlet — shipped: a `udp://` target is a global datagram outlet (stream-level, no per-peer state), so many NAT'd spokes reach one NAT'd peer holding a single `tun` device (the server's per-IP route table is GOST's). Admission is the caller's.

## License

MIT
