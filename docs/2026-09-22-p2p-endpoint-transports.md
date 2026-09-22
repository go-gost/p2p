# p2p: one endpoint, transports attached

Status: **implemented** (2026-09-23, branch `p2p-endpoint-transports`,
uncommitted). Deviations from the sketch below, all small: the in-process door
is `p2p/endpoint` (`endpoint.Endpoint`, not `p2p/tunnel` — it is the endpoint,
and the name avoids `tunnel.Tunnel`); a failed forward registration is reported
as `p2p.ErrForward` so a transport can tell it from a transient relay failure;
a closed endpoint maps to `Unavailable`, and `Endpoint.Close` closes its
attached transports (registered with `Endpoint.Attach`) before the host, so a
transport's listener cannot outlive the endpoint. The endpoint's `Host()`
accessor is how an in-module transport reaches the seam.

Verified: build/vet/gofmt clean in the workspace and with `GOWORK=off`; `-race`
tests green per package; the root dependency test green; the `stub` e2e scenario
passes (CLI, config file, token); and a loopback replica of the relay scenario
passes against a real derper — `derp_peers:1`, `direct_peers:0`, `tunnels:0`
after the request. The namespace-dependent e2e scenarios could not run in this
container (no userns / CAP_NET_ADMIN). wisper was adapted in the same change.

Original design below.

## Why

p2p is a library for third parties. gost and wisper are its first consumers, not
its definition — so the API is judged by a stranger's first read, and the import
graph is part of that API.

Two costs of the current shape fall on those strangers:

1. **Import weight.** Package `p2p` imports grpc-go, the `go-gost/plugin` proto
   module, gRPC reflection and a YAML parser, so an in-process embedder links a
   gost-specific proto module, a gRPC stack it never uses, and a config-file
   parser it never asked for. A library should make an embedder pull the engine
   and nothing else.
2. **One type, three jobs.** `Host` is the engine, the in-process API and the
   gRPC server at once, and the in-process caller reaches it through a facade
   (`host.Tunnel().Dial`). Nothing in the type says which half to use, and
   `Close` means two different things depending on which half you hold.

The fix: **one endpoint, transports attached**. `Endpoint` owns the engine, the
registry and the in-process API; a transport package serves it over a wire
protocol (`p2p/grpc` today). The root package holds only the contracts both
sides share, so it stays dependency-free.

## Current coupling (inventory)

| File | Coupled how |
|---|---|
| `host.go` | `grpc`/`ln`/`addr` fields, `Start`/`Serve`/`Addr`/`serveOn`, `grpc.ErrServerStopped`, `Status` returns `*proto.StatusReply` |
| `server.go` | embeds `proto.UnimplementedP2PServer`; `OpenTunnel`/`Status` are proto methods; validation errors are gRPC status codes. Splits: the registry half stays in the host |
| `stream.go` | the `Tunnel` RPC handler: proto stream types, `metadata`, `codes` |
| `streamconn.go`, `pipe.go` | `tunnelStream` carries `*proto.Chunk` (only `GetData()` is used) |
| `auth.go` | gRPC unary/stream interceptors |
| `config.go` | `Addr`, `Token` (transport settings), `Log`/`LogRotationConfig` and `LoadConfig` (deployment settings) |
| `provider.go` | the `Tunnel` facade over `Host`; `Close` means "listener only" here and "everything" on `Host` |
| `cmd/p2p/main.go` | `host.Start()` |
| tests | `host_test.go` (Start), `stream_test.go` (raw `grpc.Server` + `*server`), `server_test.go`/`direct_test.go` (proto types) |

The registry — `tunnelRecord`, pending GC, `--forward` listeners, udp channel
references — is **not** gRPC-specific: forwards and channels use it too. It
stays in the host.

## Target shape

```
p2p/                  contracts: Config + TLSConfig/ForwardConfig/Timeouts,
                      Status, the sentinel errors          (no implementation, no deps)
p2p/endpoint/         Endpoint: the public face of a host — identity, engine,
                      forwards, Dial/Listen (the in-process API)
p2p/grpc/             Server: the gRPC transport over an Endpoint
p2p/http/, p2p/ws/    later transports, named after their protocol
p2p/internal/host/    Host + engine + registry + data planes + the seam
cmd/p2p/              builds an Endpoint and attaches the gRPC server
```

The root package is the shared contract, so nothing in `p2p` is privileged:
importing it pulls no engine, no host, no gRPC — and no external dependency at
all. The types are *defined* there (not aliased out of `internal`), and
`internal/host` imports the root package — the dependency arrow points inward
only.

```go
// p2p — the shared contract.
type Config struct{ ... }        // + TLSConfig, ForwardConfig, Timeouts, Status
var ErrInvalidNetwork, ErrInvalidPeer, ErrUnknownTunnel, ErrTunnelAttached, ErrPeerUnreachable error

// p2p/endpoint — the endpoint, one type. It owns the host and never exposes it
// to an embedder (the Host() accessor is for in-module transports only).
// The host-level half (identity, engine, forwards) and the in-process half
// (Dial/Listen) are the same object, the way a consumer uses them.
type Endpoint struct{ ... }
func New(cfg *p2p.Config, opts ...Option) (*Endpoint, error) // WithLogger
func (e *Endpoint) Connect() error
func (e *Endpoint) Close() error                       // everything: listeners, host, engine
func (e *Endpoint) PublicKey() string
func (e *Endpoint) AddForward(listen, peerKey string) error
func (e *Endpoint) Dial(ctx context.Context, network, peer string) (net.Conn, error)
func (e *Endpoint) Listen() (net.Listener, error)
func (e *Endpoint) Status() p2p.Status

// p2p/grpc — the gRPC transport. It serves an endpoint; it never owns one.
type Server struct{ ... }
func New(ep *endpoint.Endpoint, opts ...Option) (*Server, error) // WithAddr, WithToken, WithLogger
func (s *Server) Start() (string, error)
func (s *Server) Serve(ln net.Listener) error
func (s *Server) Addr() string
func (s *Server) PublicKey() string
func (s *Server) Close() error                         // this listener only; the endpoint outlives it
```

Ownership is the rule that makes `Close` unambiguous: **the endpoint owns the
engine and everything under it; a transport owns its own listener.** Closing a
transport never touches the endpoint; closing the endpoint ends every transport
that serves it.

Each package defines its own `Option` type (a shared one would have to carry
transport-specific settings). The name `Provider` stays retired: it was rejected
as ambiguous when the Dial/Listen type became the endpoint.

### One endpoint, transports attached

The endpoint is created once and transports attach to it, so a process that both
serves the gRPC protocol and dials in-process uses **one identity, one engine,
one DERP connection, one channel per peer** — not two. That is also why the
timings in `applyTimeouts` are package-level: one endpoint per process is the
model, and a second `New` inheriting the first's timeouts is now the documented
behavior rather than a caveat.

### The seam between host and transports

The endpoint is the only public door onto the host. A transport sits on the
host's seam, which stays in `internal/host`: transports live in this module, and
the endpoint reaches the seam for them. The two-phase shape (an id issued by one
request, the carrier attached later) is for transports that separate authorize
from carry — today's gRPC transport, an HTTP transport tomorrow; the in-process
path never sees it, it dials and listens directly:

```go
// internal/host
type Stream interface { // the byte-stream half of a tunnel carrier
    Send([]byte) error
    Recv() ([]byte, error)
    Context() context.Context
}
func (h *Host) OpenTunnel(network, peer string) (string, error)      // validate + allocate a pending record
func (h *Host) AttachTunnel(id string, s Stream, abort func()) error // claim (single use) + serve
func (h *Host) Dial(ctx context.Context, network, peer string) (net.Conn, error)
func (h *Host) Listen() (net.Listener, error)
func (h *Host) PublicKey() string
func (h *Host) AddForward(listen, peerKey string) error
func (h *Host) Status() p2p.Status
```

- `streamconn.go` adapts a `Stream` to the `net.Conn` the tunnel pipe needs —
  internals unchanged, `*proto.Chunk` becomes `[]byte`.
- `pipe.go` implements `Stream` in memory for the in-process path; the payload
  copy in `Send` (the P0 aliasing fix) stays.
- Validation, claim and peer-open failures return sentinel errors, so a
  transport maps them to its own error shape without the host knowing about it:

  | host error | gRPC code (today's behavior) |
  |---|---|
  | `ErrInvalidNetwork`, `ErrInvalidPeer` | `InvalidArgument` |
  | `ErrUnknownTunnel` | `NotFound` |
  | `ErrTunnelAttached` | `AlreadyExists` |
  | `ErrPeerUnreachable` (wraps the cause) | `Unavailable` |

Rules that keep the layout honest:

- Transport packages are named after their protocol — `p2p/grpc` today,
  `p2p/http` or `p2p/ws` later — not after their role: a transport carries both
  control and data, so `control` would have been a misnomer. A package whose
  name shadows a well-known import (`grpc`, `http`) aliases that import inside
  itself.
- A transport owns its wire protocol, its dependencies (grpc, net/http, a ws
  library) and its own `Option` type. The host never learns a protocol.
- The root package stays carrier-neutral: no transport-specific type or setting
  in it. Transport settings live in the transport's own options
  (`grpc.WithAddr`, `grpc.WithToken`), and deployment settings (log, config
  file) live in the binary that deploys it (`cmd/p2p`).
- The seam is the contract. If a transport needs a primitive the host lacks —
  e.g. injecting an externally carried stream as an inbound peer stream — it is
  added to `internal/host` as a carrier-neutral primitive, not to the root.
- **Transports from outside this module are not supported.** `internal/host`
  stays internal so the seam can change without breaking anyone; a transport
  that proves generally useful is contributed here rather than maintained
  out-of-tree. This is a deliberate limit, not an oversight: it is the price of
  keeping the seam free to move.

### Config and CLI

The root `Config` carries only what the host reads: `Derp`, `Key`, `KeyHex`,
`Target`/`Targets`, `Stun`, `Direct`, `TLS`, `Timeouts`, `Forwards` (+ the
`TargetList` helper). Everything that is really the *deployment's* — `Addr`,
`Token`, `Log`/`LogConfig`/`LogRotationConfig`, and the YAML file reader
(`LoadConfig`) — moves to `cmd/p2p`, which owns its own file format:

```go
// cmd/p2p
type config struct {
    p2p.Config `yaml:",inline"`
    Addr  string     `yaml:"addr,omitempty"`
    Token string     `yaml:"token,omitempty"`
    Log   *logConfig `yaml:"log,omitempty"`
}
```

So the YAML keys stay where they are (`addr:`, `token:`, `log:` at the top
level) while the library stops carrying them, and the root package ends up with
**no external dependency at all** (the yaml reader was its only one). The
`127.0.0.1:8003` default lives in three places today (the flag, the CLI's config
default, `applyDefaults`); the library-side copy becomes `grpc.WithAddr`'s
default and `applyDefaults` drops it, so the CLI keeps its own default and the
host has none.

```go
// cmd/p2p
ep, err := endpoint.New(&cfg.Config, endpoint.WithLogger(slog.Default()))
srv, err := grpc.New(ep, grpc.WithAddr(cfg.Addr), grpc.WithToken(cfg.Token))
addr, err := srv.Start()
// shutdown: srv.Close(), then ep.Close()
```

### Docs are part of this change

A library's docs are its front door, and today they document the shape being
replaced. The move is not done until these land in the same change:

- `doc.go` for each public package (`p2p`, `p2p/endpoint`, `p2p/grpc`): what the
  package is for, the two usage shapes, and the trust boundary.
- Every exported symbol documented, per the project's Go doc standard.
- `README.md` and `README.zh-CN.md`: the "In-process embedding" section rewritten
  for the endpoint API, plus a short "Transports" subsection showing
  `grpc.New(ep, …)`.
- `docs/embedding.md`: a third-party guide — key/identity handling, forwards,
  the process-wide timeouts (one endpoint per process), and what the library
  deliberately does not do (encryption, discovery, admission).
- `CLAUDE.md`: rewritten for the new layout; it describes the flat package today.

## Behavior that must not change

- The proto contract and wire behavior (`OpenTunnel`, the `Tunnel` stream, the
  `id` metadata credential, single use, `NotFound`/`AlreadyExists`).
- The pending GC (~10 s) and the stream-lifetime-is-tunnel-lifetime rule.
- udp channel semantics: the `Tunnel` stream is the channel's local edge.
- `--forward` bridging and its half-close rules.
- The trust boundary: unauthenticated by default, loopback default, `--token`.
- The in-process API as callers see it, modulo the type merge below: today's
  `Host` plus `Host.Tunnel()` become one `Endpoint`, and its `Close` closes the
  endpoint (the inbound listener included) rather than the listener alone.

## Consumer impact

- **wisper**: `p2p.New(...)` becomes `endpoint.New(cfg, …)` (import
  `github.com/go-gost/p2p/endpoint`, aliased — wisper's own package is
  `tunnel`); `host.Connect()`/`PublicKey()`/`Close()` become
  `ep.Connect()`/`PublicKey()`/`Close()`; `host.Tunnel().Dial/Listen` become
  `ep.Dial`/`ep.Listen`; the P2P registry takes the endpoint itself
  (`Register(name, ep)`). The registry interface is `Dial` + `Close`
  (`x/p2p/tunnel_dialer.go`), which the endpoint satisfies — but note the
  interface's `Close` now means endpoint teardown: nothing calls it on a
  registered endpoint today (verified), and the doc comment on the registration
  site must say so. `p2p.Config{...}` compiles unchanged.
- **x**: unaffected — `x` does not import `github.com/go-gost/p2p` at all
  (`x/p2p/tunnel_dialer.go` declares its own `Dial`+`Close` interface and
  wisper registers into it). No `go.mod` change.
- **cmd/p2p**: `host.Start()` → `endpoint.New(...)` + `grpc.New(ep, …)` +
  `srv.Start()`; the config file reader, `Addr`/`Token` and the log settings
  become its own.

## Tests

- `internal/host`: the existing coverage moves with the code (host, server,
  pipe, direct, udp, frame, engine, and the config-default/timeout tests), with
  byte-based fake streams where proto ones were used; new tests for the seam —
  `OpenTunnel` validation sentinels, `AttachTunnel` claim semantics (unknown
  id, second claim), `Status` fields.
- `p2p`: the root package holds types and `TargetList` only, so its tests are
  the contract-level ones (plus error identity).
- `p2p/endpoint`: the endpoint's own tests (Dial/Listen/Close, options, the
  shared-endpoint rule: closing a transport leaves the endpoint serving).
- `p2p/grpc`: `stream_test.go` and the `Start`/`Serve` tests move here (they are
  the transport's contract tests), plus the interceptor tests.
- `cmd/p2p`: the config-file test (`TestLoadConfig`) moves here with the reader.
- e2e (`tests/e2e`, CLI + gRPC helper): unchanged, must pass as-is.
- **Dependency test, permanent**: a test in the root package runs
  `go list -deps .` (skipped when the `go` tool is not on `PATH`) and fails if
  any dependency is outside the standard library. "Root has no dependencies" is
  a promise to third parties, so it needs a regression guard, not a one-off
  check.

## Versioning

p2p v0.5.0. Breaking: `p2p.Host` is gone — its public half is
`endpoint.Endpoint` (in-process) and its gRPC half is `grpc.Server`;
`Host.Tunnel()` folds into the endpoint; `Status` is a `p2p` type instead of the
proto reply; `p2p.Config` loses `Addr`/`Token`/`Log` and `p2p.LoadConfig` (they
move to `cmd/p2p` — the config *file* keeps its keys, so existing deployments'
YAML still loads; the Go-level `LoadConfig` call disappears, which is the one
loss for library users). The proto and the wire do not change, so GOST's plugin
client and existing deployments keep working.

The endpoint/transport API is intended to stabilize: once a third party other
than wisper depends on it, further breaking changes cost strangers, so anything
we know we want (the seam's error set, the ownership rule above) should land
before that point.

## Non-goals

- No proto or wire change; no data-plane, security or trust-boundary change.
- The registry (records, GC, forwards, channels) stays in the host.
- No new transport in this change — the point is that adding one later is a new
  sibling package over the same seam, nothing more.
- No third-party transports: the seam stays in `internal/host` (see above).
- No change to `x/p2p/`, `plugin/`, or wisper beyond the adaptation above.
