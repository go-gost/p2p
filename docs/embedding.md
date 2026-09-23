# Embedding p2p in a third-party program

This guide is for an application that wants p2p's connectivity without running
the `p2p` binary next to it: the packages, the shapes, the identity, the knobs,
and the boundaries the library deliberately does not cross.

## Packages

| Package | What it is | Dependencies |
|---|---|---|
| `github.com/go-gost/p2p` | the contracts: `Config`, `Status`, the sentinel errors | standard library only |
| `github.com/go-gost/p2p/endpoint` | the endpoint: identity, relay engine, forwards, `Dial`/`Listen`, a STUN probe | engine (kcp, smux, websocket) |
| `github.com/go-gost/p2p/grpc` | the gRPC transport: serves an endpoint over the GOST plugin protocol | grpc-go, the plugin proto |
| `github.com/go-gost/p2p/internal/…` | implementation detail | not importable, not supported |

Importing the contracts does not pull the engine or a transport — a test in the
root package enforces it. Importing `endpoint` does not pull gRPC.

## One endpoint, transports attached

An endpoint is created once and owns everything: the identity, the relay
connection, the forwards, the tunnel registry. A transport *serves* an endpoint
and owns only its own listener. Attach the gRPC transport and the same process
serves GOST's plugin client **and** dials in-process, on one identity and one
relay connection.

```go
ep, err := endpoint.New(cfg)                    // no I/O yet
srv, err := grpc.New(ep, grpc.WithAddr("127.0.0.1:8003"), grpc.WithToken(tok))
addr, err := srv.Start()                        // binds the control plane, connects the endpoint
```

Closing a transport stops its listener; closing the endpoint closes its
transports and then the engine. `Connect` is idempotent and safe to call from
either side; a failed relay connect is not fatal (the engine retries), while a
failed forward registration wraps `p2p.ErrForward` and is returned from
`Start`/`Serve` — `errors.Is(err, p2p.ErrForward)` is the test.

## Identity

- The endpoint's address is its curve25519 public key: `PublicKey()` is the
  base64 string peers put in their own configuration.
- `Config.Key` is a key file, created (0600) on first use if missing;
  `Config.KeyHex` is a 32-byte hex key held in memory — for tests and
  short-lived processes. No relay configured (stub mode) means no identity and
  an empty `PublicKey()`.
- One endpoint per process is the model (see Timings). Two endpoints sharing one
  key file in one process is not a supported configuration.

## Shapes

**Dial out, no control plane** — the embedder's own protocol rides inside the
tunnel:

```go
ep, _ := endpoint.New(&p2p.Config{Derp: derpURL, Key: keyPath})
_ = ep.Connect()
conn, err := ep.Dial(ctx, "tcp", peerKey)   // the conn IS the tunnel
```

`network` is `tcp` or a udp variant; a udp tunnel preserves datagram
boundaries. `ctx` bounds only the call — close the conn to end the tunnel.

**Take inbound tunnels** — relay mode only, mutually exclusive with
`Config.Targets`:

```go
ln, err := ep.Listen()      // call before Connect
c, err := ln.Accept()       // c.RemoteAddr() is the peer's base64 key
```

A `tcp` tunnel arrives as a byte stream. A udp tunnel arrives as a **datagram
conn**: it satisfies `net.PacketConn` (which is how a service stack tells udp
from tcp), every Read returns one datagram and every Write sends one, and the
2-byte framing on the wire is parsed for you. Datagrams larger than the read
buffer are truncated, as on a UDP socket.

**Bridge to local services** — `Config.Target`/`Targets` make the endpoint
bridge each inbound tunnel to a local target for that tunnel's lifetime
(`tcp://host:port`, `udp://host:port`). With targets configured the endpoint
serves inbound traffic itself; `Listen` then reports a conflict.

**Static forwards** — `Config.Forwards` (or `AddForward`) binds a local port and
bridges every accepted connection to a peer key. Relay mode only; a forward
failure is a configuration error and fails startup.

## Timings

`Config.Timeouts` tunes deployment-dependent windows (punch, seed, backoff,
relay keepalive, smux keepalive). They are **process-wide**: applied when an
endpoint is created, and a later endpoint inherits the values already applied.
One endpoint per process is the model — a process that builds two must give them
identical timeouts (or none). Internal mechanism timeouts are not configurable.

The two smux keepalives are separate: `smux` is the relay session's, `directSmux`
the hole-punched session's. The direct one defaults much tighter (2s/6s against
10s/30s) and is **negotiated**: smux answers a NOP with nothing, so a session is
kept alive by the frames the *peer* sends, and a timeout shorter than the peer's
ping interval tears the session down on a loop. Both ends advertise the pair
through the capability bitfield and a peer that does not set the bit gets the
relay's pair instead — so the tighter values apply only when both sides run a
version that has them. With both on it, smux notices a silent session after
roughly 2x the timeout, so the direct default gives ~12s. Widening it costs
latency in that window; narrowing it risks giving up a path that a burst of loss
merely stalled, at the price of a relay fallback and a re-punch.

## Direct path

`Config.Direct` (nil = on) attempts a hole-punched path and falls back to the
relay; `Config.Stun` (host:port) is the IPv4 candidate source, and the IPv6 path
needs no STUN. `endpoint.StunLookup(ctx, addr)` probes a STUN server the way the
engine does — it returns the public address the server sees, which is what a
punch needs — so an embedder can validate a `Stun` value before starting:

```go
mapped, err := endpoint.StunLookup(ctx, "derp.example:3478")
```

The probe dials its own socket: the address it reports is that socket's mapping,
not the one a later punch will use.

## Trust boundary

- The control plane is **unauthenticated by default** and anyone who can reach
  the listen address can make the endpoint dial out (an SSRF-shaped surface:
  unlike other plugin hosts, this one dials *out*). The loopback default
  (`127.0.0.1:8003`) is the security boundary; `grpc.WithToken` adds a
  constant-time token check on every RPC, and a cross-machine deployment needs
  the token **plus** control TLS in front of the server (the token travels
  plaintext).
- The data plane is **plaintext**, on the relay and on the hole-punched path
  alike. Confidentiality is the inner protocol's job: run a `tls`/`mtls`/`wss`
  dialer inside the tunnel. The transports are intentionally plain.
- A tunnel id is a single-use credential; the stream bound to it is the tunnel,
  and its end is the teardown.

## What the library does not do

Deliberate scope, not gaps:

- **No encryption** of the relay or direct path (see above).
- **No peer discovery**: peers are addressed by their base64 key. A
  human-friendly name belongs in the caller's own configuration.
- **No admission control**: who may use a `udp://` target outlet is the caller's
  decision (a tun `auther`, the relay's `-verify-clients`, port binding or
  firewall). An unauthenticated outlet is an unauthenticated service on the data
  plane.
- **No third-party transports**: the seam between an endpoint and a transport
  lives in `p2p/internal/host`, so it cannot be imported from outside the
  module. (A value from `Endpoint.Host()` still has callable methods — Go
  resolves them without naming the type — but reaching through it is
  unsupported and the seam changes without notice.) A transport that proves
  generally useful is contributed here.
- **No symmetric-NAT traversal**: a peer behind a symmetric NAT stays on the
  relay permanently.
