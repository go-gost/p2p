package host

import (
	"testing"
)

// TestPeerDiagnosticsReportsQUICStats pins the QUIC status surface: in QUIC
// mode a connected peer names its transport, carries the live QUIC connection's
// stats (role, path, RTT, streams, bytes) and has no KCP session to report. In
// KCP mode the same fields say "kcp" and carry no QUIC stats, so a reader can
// tell the two modes apart from one snapshot.
func TestPeerDiagnosticsReportsQUICStats(t *testing.T) {
	t.Run("relay", func(t *testing.T) {
		a, b := newQUICFailurePair(t, false)
		conn, err := a.OpenStream(b.PublicKey())
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		roundTrip(t, conn, "quic-relay-status")
		conn.Close()

		srv := newServer(a)
		t.Cleanup(srv.close)
		st := srv.status()

		if st.Transport != "quic" {
			t.Fatalf("Status.Transport = %q, want quic", st.Transport)
		}
		key := b.PublicKey()
		d, ok := st.PeerDiagnostics[key]
		if !ok {
			t.Fatalf("no diagnostic for peer %s: %+v", key, st.PeerDiagnostics)
		}
		if d.Path != transportRelay {
			t.Fatalf("diagnostic path = %q, want %q", d.Path, transportRelay)
		}
		if d.Transport != "quic" {
			t.Fatalf("diagnostic transport = %q, want quic", d.Transport)
		}
		if d.DirectTransport != "quic" {
			t.Fatalf("direct transport = %q, want quic", d.DirectTransport)
		}
		if d.QUIC == nil {
			t.Fatal("QUIC stats are nil for a peer on a live QUIC connection")
		}
		if !d.QUIC.Live {
			t.Fatal("QUIC.Live = false for an established pair")
		}
		if d.QUIC.Path != quicPathRelay {
			t.Fatalf("QUIC.Path = %q, want %q", d.QUIC.Path, quicPathRelay)
		}
		if d.QUIC.Role != quicRoleName(a.getQUIC(b.pub).role) {
			t.Fatalf("QUIC.Role = %q, want %q", d.QUIC.Role, quicRoleName(a.getQUIC(b.pub).role))
		}
		if d.QUIC.RTT < 0 {
			t.Fatalf("QUIC.RTT = %v, want non-negative", d.QUIC.RTT)
		}
		if d.QUIC.Streams < 0 {
			t.Fatalf("QUIC.Streams = %d, want non-negative", d.QUIC.Streams)
		}
		if d.QUIC.BytesSent == 0 || d.QUIC.BytesRcvd == 0 {
			t.Fatalf("QUIC byte counters = %d/%d, want traffic in both directions",
				d.QUIC.BytesSent, d.QUIC.BytesRcvd)
		}
		if d.RelayKCP.Live {
			t.Fatal("RelayKCP.Live = true in QUIC mode, want no KCP session")
		}
		if d.SessionState != "up" {
			t.Fatalf("SessionState = %q, want up", d.SessionState)
		}
		if d.TransportError != "" {
			t.Fatalf("TransportError = %q, want empty for a healthy pair", d.TransportError)
		}
		if got := st.PeerTransports[key]; got != transportRelay {
			t.Fatalf("PeerTransports[%s] = %q, want %q", key, got, transportRelay)
		}
		if st.DerpPeers != 1 || st.DirectPeers != 0 {
			t.Fatalf("peers = %d direct / %d relay, want 0/1", st.DirectPeers, st.DerpPeers)
		}
	})

	t.Run("direct", func(t *testing.T) {
		a, b := newQUICFailurePair(t, true)
		establishQUICRelayAndDirect(t, a, b)

		srv := newServer(a)
		t.Cleanup(srv.close)
		st := srv.status()

		key := b.PublicKey()
		d, ok := st.PeerDiagnostics[key]
		if !ok {
			t.Fatalf("no diagnostic for peer %s: %+v", key, st.PeerDiagnostics)
		}
		if d.Path != transportDirect {
			t.Fatalf("diagnostic path = %q, want %q", d.Path, transportDirect)
		}
		if d.QUIC == nil || d.QUIC.Path != quicPathDirect {
			t.Fatalf("QUIC stats = %+v, want path %q", d.QUIC, quicPathDirect)
		}
		if got := st.PeerTransports[key]; got != transportDirect {
			t.Fatalf("PeerTransports[%s] = %q, want %q", key, got, transportDirect)
		}
		if st.DirectPeers != 1 || st.DerpPeers != 0 {
			t.Fatalf("peers = %d direct / %d relay, want 1/0", st.DirectPeers, st.DerpPeers)
		}
	})

	t.Run("kcp", func(t *testing.T) {
		a, b, _ := newEncryptedPair(t)
		conn, err := a.OpenStream(b.PublicKey())
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		roundTrip(t, conn, "kcp-status")
		conn.Close()

		srv := newServer(a)
		t.Cleanup(srv.close)
		st := srv.status()

		if st.Transport != "kcp" {
			t.Fatalf("Status.Transport = %q, want kcp", st.Transport)
		}
		d, ok := st.PeerDiagnostics[b.PublicKey()]
		if !ok {
			t.Fatalf("no diagnostic for peer %s", b.PublicKey())
		}
		if d.Transport != "kcp" {
			t.Fatalf("diagnostic transport = %q, want kcp", d.Transport)
		}
		if d.DirectTransport != "kcp" {
			t.Fatalf("direct transport = %q, want kcp", d.DirectTransport)
		}
		if d.QUIC != nil {
			t.Fatalf("QUIC stats = %+v, want nil in KCP mode", d.QUIC)
		}
	})
}
