package host

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/doctor"
	"github.com/go-gost/p2p/internal/derpclient"
)

func TestQUICTransportErrorReasonKeepsTypedReason(t *testing.T) {
	err := quicFailure("no-quic-identity",
		fmt.Errorf("%w: peer x: quic identity is not configured", p2p.ErrTransportUnsupported))
	if got := quicTransportErrorReason(err); got != "no-quic-identity" {
		t.Fatalf("reason = %q, want no-quic-identity", got)
	}
	if !errors.Is(err, p2p.ErrTransportUnsupported) {
		t.Fatal("typed reason broke errors.Is for the wrapped sentinel")
	}
}

// TestPeerDiagnosticsReportsQUICTransportError covers the failure path a real
// status used to hide: a peer whose QUIC establishment failed has no live
// transport entry, but its diagnostic must still carry the reason and must not
// inflate the connected-peer gauges. The doctor renders the same status.
func TestPeerDiagnosticsReportsQUICTransportError(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	privA, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, err := derpclient.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newQUICTestEngine(t, url, "", privA)
	b := newEngine(url, "", privB, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(b.Close)
	if err := a.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := b.Connect(); err != nil {
		t.Fatal(err)
	}

	// b is a KCP-only peer: its caps frame carries no QUIC bit, so a's
	// establishment is refused as soon as those caps arrive.
	if err := b.sendCaps(a.pub, capsInfo{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return peerCapsSeen(a, b.pub) })
	if _, err := a.OpenStream(b.PublicKey()); err == nil ||
		!errors.Is(err, p2p.ErrTransportUnsupported) {
		t.Fatalf("OpenStream error = %v, want ErrTransportUnsupported", err)
	}
	waitFor(t, 5*time.Second, func() bool {
		return a.quicTransportError(b.pub) == "peer-no-quic"
	})

	srv := newServer(a)
	t.Cleanup(srv.close)
	st := srv.status()
	key := b.PublicKey()
	d, ok := st.PeerDiagnostics[key]
	if !ok {
		t.Fatalf("no diagnostic for the failed peer %s: %+v", key, st.PeerDiagnostics)
	}
	if d.Path != "" {
		t.Fatalf("failed peer path = %q, want empty (no live transport)", d.Path)
	}
	if d.Transport != "quic" {
		t.Fatalf("failed peer transport = %q, want quic", d.Transport)
	}
	if d.DirectTransport != "quic" {
		t.Fatalf("failed peer direct transport = %q, want quic", d.DirectTransport)
	}
	if d.TransportError != "peer-no-quic" {
		t.Fatalf("TransportError = %q, want peer-no-quic", d.TransportError)
	}
	// The failure is diagnostic-only: the connected-peer surface stays empty.
	if _, ok := st.PeerTransports[key]; ok {
		t.Fatalf("failed peer leaked into PeerTransports: %+v", st.PeerTransports)
	}
	if st.DerpPeers != 0 || st.DirectPeers != 0 {
		t.Fatalf("failed peer inflated the gauges: %d direct / %d relay",
			st.DirectPeers, st.DerpPeers)
	}

	out := doctor.Report(st, doctor.Options{InProcess: true})
	for _, want := range []string{
		"transport error:",
		"peer-no-quic",
		"no connected transport (quic: peer-no-quic)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor report is missing %q:\n%s", want, out)
		}
	}
}

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
		// Sample while the stream is open: a counter read after Close would be
		// zero whether or not it was ever incremented.
		waitFor(t, 5*time.Second, func() bool {
			pa, pb := a.getQUIC(b.pub), b.getQUIC(a.pub)
			return pa != nil && pb != nil &&
				pa.streams.Load() == 1 && pb.streams.Load() == 1
		})
		// A completed round trip must have produced a real RTT sample on both
		// ends before the status is read.
		waitFor(t, 5*time.Second, func() bool {
			pa, pb := a.getQUIC(b.pub), b.getQUIC(a.pub)
			return pa != nil && pb != nil &&
				pa.stats().RTT > 0 && pb.stats().RTT > 0
		})

		srv := newServer(a)
		t.Cleanup(srv.close)
		peerSrv := newServer(b)
		t.Cleanup(peerSrv.close)
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
		if d.QUIC.RTT <= 0 {
			t.Fatalf("QUIC.RTT = %v, want a positive sample after a round trip", d.QUIC.RTT)
		}
		if d.QUIC.Streams != 1 {
			t.Fatalf("QUIC.Streams = %d while one stream is open, want 1", d.QUIC.Streams)
		}
		if d.QUIC.BytesSent == 0 || d.QUIC.BytesRcvd == 0 {
			t.Fatalf("QUIC byte counters = %d/%d, want traffic in both directions",
				d.QUIC.BytesSent, d.QUIC.BytesRcvd)
		}
		// The accepting side counts the same stream, so a counter that only
		// works on the opener would still pass a one-sided assertion.
		peerDiag, ok := peerSrv.status().PeerDiagnostics[a.PublicKey()]
		if !ok {
			t.Fatalf("no peer diagnostic on the accepting side: %+v",
				peerSrv.status().PeerDiagnostics)
		}
		if peerDiag.QUIC == nil || peerDiag.QUIC.Streams != 1 {
			t.Fatalf("accepting side QUIC stats = %+v, want 1 open stream", peerDiag.QUIC)
		}
		if peerDiag.QUIC.RTT <= 0 {
			t.Fatalf("accepting side QUIC.RTT = %v, want a positive sample", peerDiag.QUIC.RTT)
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

		conn.Close()
		// Both counters must fall back once the stream ends: a pair-owned
		// counter that never released would read 1 forever.
		waitFor(t, 5*time.Second, func() bool {
			pa, pb := a.getQUIC(b.pub), b.getQUIC(a.pub)
			return pa != nil && pb != nil &&
				pa.streams.Load() == 0 && pb.streams.Load() == 0
		})
		closed := srv.status().PeerDiagnostics[key]
		if closed.QUIC == nil || closed.QUIC.Streams != 0 {
			t.Fatalf("QUIC.Streams after Close = %+v, want 0", closed.QUIC)
		}
		closedPeer := peerSrv.status().PeerDiagnostics[a.PublicKey()]
		if closedPeer.QUIC == nil || closedPeer.QUIC.Streams != 0 {
			t.Fatalf("accepting side QUIC.Streams after Close = %+v, want 0", closedPeer.QUIC)
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
