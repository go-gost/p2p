# p2p end-to-end tests

Black-box tests for the `gost p2p` host. They build the real binaries, start a
real [derper](https://github.com/go-gost/derper) relay, put the two peers in
separate network namespaces, and drive real traffic through the tunnel. Every
feature the host advertises is exercised over the wire, not mocked.

These are **not a CI gate**: hole punching and STUN are timing and
network-topology sensitive, and the suite needs root or a user namespace, plus
Docker to extract the `derper` binary. `go test ./...` skips them by default.

## Prerequisites

- Linux with `CAP_NET_ADMIN` (run as root, or where `unshare -Ur -n` works) and
  `/dev/net/tun` for the tun scenarios.
- A Go toolchain (`go` on `PATH` or at `~/.local/go/bin/go`).
- `docker` to extract the relay binary, `openssl` for certs, `curl`, `ping`.
- Two network namespaces. `ip netns` is used when it works; otherwise the suite
  falls back to `unshare`/`nsenter` holder processes.

## Running

```sh
cd p2p/tests/e2e

./run.sh                     # all scenarios
./run.sh --list              # names only
./run.sh --scenario udp-tun  # one scenario
./run.sh --keep              # keep logs and binaries
./run.sh --skip-build        # reuse $P2P_E2E_WORK/bin
./run.sh --gost-bin /path/to/gost --p2p-bin /path/to/p2p
```

Through `go test`:

```sh
P2P_E2E=1 go test ./tests/e2e -v
P2P_E2E=1 P2P_E2E_ARGS="--scenario ipv6-direct --keep" go test ./tests/e2e -v
```

Artifacts land in `$P2P_E2E_WORK` (default `/tmp/p2p-e2e`): built binaries under
`bin/`, the extracted relay under `derper-root/`, and per-run logs under
`runs/<timestamp>-<pid>-<rand>/logs/` (the random suffix stops a reused PID from
colliding with a previous run). The last five runs are kept.

## Scenarios

| Scenario | What it proves |
|----------|----------------|
| `stub` | The loopback bridge (`peer = host:port`) carries HTTP and a 1 MiB bulk transfer; `--token` is enforced (matching token works, missing token is rejected); `-C` config behaves like the equivalent flags. |
| `derp-relay` | With a real derper and `--direct=false`, the relay path carries traffic, `Status` reports `derp_peers`, and a finished non-mux tunnel leaves no residue (`tunnels` returns to 0). |
| `derp-direct` | STUN + UDP hole punch establishes a direct session (`status.direct_peers`), and traffic survives killing the relay (the session is genuinely direct). |
| `forward` | `--forward listen=peerkey` exposes a raw TCP port bound to a peer key; a plain TCP client reaches a service on the peer. |
| `inner-matrix` | The `tcp`, `tls`, `ws`, `mtcp`, `mtls`, and `mws` inner dialers each carry HTTP to peer gost listeners over one relay pair. |
| `udp-tun` | The datagram link backs a point-to-point tun link (both ends tun clients, `udp` inner dialer): bidirectional ICMP across the link, and the link comes up on both sides. |
| `udp-outlet` | A `udp://` target outlet: a tun **server** behind the tunnel with a shared passphrase; a remote spoke registers a keepalive route and reaches both the server address and a LAN address behind it. |
| `ipv6-direct` | With no STUN server, a global IPv6 egress is enough to select a direct path (`direct_peers`); the peer's announced candidate is an `fd00::` address, proving the dial was IPv6 and not a v4 fallback. |

## Topology

```
root netns
  p2p-e2e-br (bridge)  10.99.0.1/24   [+ fd00::1/64 in ipv6-direct]
  derper               10.99.0.254:443 (wss)          [+ :3478 stun]
  helper http          10.99.0.1:18081
  ├── veth ─ netns A   10.99.0.2/24   [+ fd00::2/64 in ipv6-direct]
  └── veth ─ netns B   10.99.0.3/24   [+ fd00::3/64 in ipv6-direct]
```

Both hosts share one L2 segment. This exercises the punch mechanism and direct
path selection but **not** NAT translation: candidates are directly reachable,
which is what lets the suite run deterministically without simulating a CGNAT.
A router-namespace NAT model would be an addition, not a replacement.

The two p2p hosts publish base64 public keys in their logs; the suite extracts
them and uses them as chain node addresses (DERP mode). The `helper` sidecar
provides the pieces a shell script otherwise lacks: a `Status` RPC client, an
HTTP echo server (`/` and a 1 MiB `/bulk`), and a UDP echo server.

## Notes

- **PID tracking, not `pkill`.** All namespaces share one PID namespace, so
  `pkill -f <binary>` would kill both sides. `run.sh` records every PID it
  starts and kills them individually; teardown also removes the bridge,
  veths, and namespaces so a crashed run cannot poison the next one.
- **Tun tests need `CAP_NET_ADMIN`** inside the namespaces; the netns setup
  grants it.
- **IPv6 DAD delay.** Netns addresses are `tentative` for ~1 s; a tentative
  address is not a usable egress source, so `ipv6-direct` waits for duplicate
  address detection before starting the hosts.

### Regression found by these tests

`ipv6-direct` originally always failed: `detectV6Egress` used
`"2001:4860:4860::8888:53"`, which `net.ResolveUDPAddr("udp6", …)` rejects with
*"too many colons in address"*, so `v6Available` was always false and direct was
never attempted. The address needs brackets (`[2001:4860:4860::8888]:53`). The
in-tree unit tests substitute the `v6Egress` package var, so they could not
catch it; `TestV6ProbeAddrResolves` now guards the address itself.
