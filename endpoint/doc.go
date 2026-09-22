// Package endpoint is the in-process door onto a p2p endpoint: one identity, one
// relay engine (when a relay is configured), its static forwards, and the API
// to dial tunnels and take inbound ones with no wire protocol in between.
//
// A transport (github.com/go-gost/p2p/grpc) serves the same endpoint, so a
// process that both serves the plugin protocol and dials in-process uses one
// identity, one relay connection and one channel per peer. One endpoint per
// process is the model: the timing knobs are process-wide (see
// p2p.TimeoutsConfig).
//
// Trust boundary: nothing here authenticates a peer — reachability is this
// package's job, confidentiality is the inner protocol's (a tls/mtls/wss dialer
// above the tunnel). A listener handed out by Listen accepts any peer that
// knows the endpoint's public key.
package endpoint
