// Package p2p implements a peer-to-peer tunnel host: it exposes gRPC tunnels
// to a peer and bridges each one to a local target, using a DERP relay for
// rendezvous and, optionally, a hole-punched direct path.
//
// It runs in two modes. With Config.Derp set, peers are addressed by base64
// curve25519 public key and the relay/hole-punch engine carries the tunnel;
// with it empty ("stub" mode) the peer is a plain host:port dialled directly.
//
// The package is a library. The standalone binary lives in cmd/p2p and is only
// a flag/config front end over New. An embedder that wants tunnels without a
// separate process uses:
//
//	host, err := p2p.New(&p2p.Config{Derp: url, KeyHex: hexKey})
//	if err != nil {
//		return err
//	}
//	defer host.Close()
//	if err := host.Connect(); err != nil { // engine + configured forwards
//		return err
//	}
//	conn, err := host.Tunnel().Dial(ctx, "tcp", peerKey)
//
// Tunnel opens (and listens for) tunnels in-process over an in-memory stream;
// the gRPC control plane (Start/Serve) is only needed by out-of-process
// clients. Both paths run the same data-plane code, so tunnel semantics do not
// depend on the carrier.
package p2p
