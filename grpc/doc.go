// Package grpc serves a p2p endpoint over the GOST p2p plugin protocol:
// OpenTunnel authorizes a tunnel and issues its id, and the Tunnel bidi stream
// bound to that id carries the tunnel's data. The transport owns its listener,
// its token check and its wire format; the endpoint owns the engine.
//
// The package is named after its protocol, so it aliases google.golang.org/grpc
// as ggrpc inside itself.
//
// Trust boundary: the control channel is unauthenticated by default — anyone
// who can reach the listen address can make the endpoint dial out (an
// SSRF-shaped surface, unlike other plugin hosts this one dials *out*), so the
// loopback default address is the security boundary. WithToken enables a
// constant-time token check on every RPC, unary and stream alike. The token
// travels over a plaintext channel, so a cross-machine deployment needs the
// token *plus* control TLS in front of this server.
package grpc
