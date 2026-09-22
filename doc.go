// Package p2p is the contract layer of the p2p library: the configuration an
// endpoint reads, the status it reports, and the sentinel errors callers match
// on. It holds no implementation and no dependency outside the standard
// library, so importing it never pulls an engine, a transport, or a parser.
//
// An endpoint is built from a Config and used in one of two shapes:
//
//   - in-process (github.com/go-gost/p2p/endpoint): the caller dials tunnels
//     and takes inbound ones directly, with no wire protocol in between;
//   - over a wire protocol (github.com/go-gost/p2p/grpc): a transport serves
//     the same endpoint so a remote client — GOST's p2p plugin client — can
//     open tunnels to it.
//
// Both shapes share one endpoint, so a process that does both uses one
// identity and one relay connection.
//
// Trust boundary: the data plane is plaintext and the control plane is
// unauthenticated by default — the loopback default listen address is the
// security boundary. Confidentiality is the inner protocol's job; see the
// package documentation of endpoint and grpc for the specifics.
package p2p
