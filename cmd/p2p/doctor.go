// Doctor mode: a read-only client of a running host's gRPC Status RPC that
// renders one pasteable diagnostic report, with verdicts. It starts no host —
// doctor dials the control plane, formats the reply, and exits. The report
// itself is rendered by the shared, pure github.com/go-gost/p2p/doctor package.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	"github.com/go-gost/p2p"
	"github.com/go-gost/p2p/doctor"
	"github.com/go-gost/p2p/internal/host"
	pb "github.com/go-gost/plugin/p2p/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// runDoctor implements `p2p doctor`: query a running host's control plane and
// print one diagnostic report. It exits after printing — no host is started.
func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: p2p doctor --addr <host:port> [--token <t>] [--peer <key>] [-C <config>] [--key <file>] [--derp <url>] [--stun <addr>]\n")
		fs.PrintDefaults()
	}
	addr := fs.String("addr", "", "running host's gRPC control-plane address (host:port)")
	token := fs.String("token", "", "control-plane auth token; empty when the host checks none")
	peer := fs.String("peer", "", "narrow the report to one peer (base64 public key)")
	keyFile := fs.String("key", "", "identity key file, to name the local key; overrides the config's key")
	derpURL := fs.String("derp", "", "relay URL to name; overrides the config's derp")
	stunAddr := fs.String("stun", "", "STUN address to name; overrides the config's stun")
	configFile := fs.String("C", "", "config file (YAML) for the local identity and the relay/STUN names")
	fs.Parse(args)

	if *addr == "" {
		fmt.Fprintln(os.Stderr, "doctor: --addr is required (the running host's control-plane address)")
		os.Exit(2)
	}

	var cfg config
	if *configFile != "" {
		c, err := loadConfig(*configFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "doctor: "+err.Error())
			os.Exit(1)
		}
		cfg = *c
	}
	opts := doctor.Options{
		Version:  doctorVersion(),
		Host:     *addr,
		RelayURL: firstNonEmpty(*derpURL, cfg.Derp),
		STUN:     firstNonEmpty(*stunAddr, cfg.Stun),
		Direct:   cfg.Direct,
		Peer:     *peer,
	}
	if key, err := host.PublicKeyFile(firstNonEmpty(*keyFile, cfg.Key)); err == nil {
		opts.Identity = key
	} else {
		opts.Identity = "(unresolved: " + err.Error() + ")"
	}

	st, err := fetchStatus(*addr, *token)
	if err != nil {
		fmt.Fprintln(os.Stderr, "doctor: query "+*addr+": "+err.Error())
		os.Exit(1)
	}
	fmt.Print(doctor.Report(st, opts))
}

// fetchStatus reads one Status snapshot from a running host's control plane.
func fetchStatus(addr, token string) (p2p.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return p2p.Status{}, err
	}
	defer conn.Close()
	if token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "token", token)
	}
	reply, err := pb.NewP2PClient(conn).Status(ctx, &pb.StatusRequest{})
	if err != nil {
		return p2p.Status{}, err
	}
	return statusFromReply(reply), nil
}

// statusFromReply maps the wire reply onto the in-process Status the formatter
// reads. The proto carries no per-peer transports or encryption, so those
// fields stay at their zero value; the relay's liveness is carried (once the
// plugin release ships the added fields).
func statusFromReply(r *pb.StatusReply) p2p.Status {
	st := p2p.Status{
		Tunnels:        int(r.GetTunnels()),
		DirectPeers:    int(r.GetDirectPeers()),
		DerpPeers:      int(r.GetDerpPeers()),
		PunchAttempts:  r.GetPunchAttempts(),
		PunchSuccess:   r.GetPunchSuccess(),
		StreamsDirect:  r.GetStreamsDirect(),
		StreamsDerp:    r.GetStreamsDerp(),
		EncryptedPeers: int(r.GetEncryptedPeers()),
		PlaintextPeers: int(r.GetPlaintextPeers()),
		RelayConnected: r.GetRelayConnected(),
		RelayError:     r.GetRelayError(),
	}
	if pd := r.GetPeerDiagnostics(); len(pd) > 0 {
		st.PeerDiagnostics = make(map[string]p2p.PeerDiagnostic, len(pd))
		for _, d := range pd {
			st.PeerDiagnostics[d.GetPeer()] = p2p.PeerDiagnostic{
				Path:        d.GetPath(),
				Reason:      d.GetReason(),
				State:       d.GetState(),
				Failed:      d.GetFailed(),
				LastError:   d.GetLastError(),
				PeerAddr:    d.GetPeerAddr(),
				Candidates:  int(d.GetCandidates()),
				Caps:        d.GetCaps(),
				SessionAge:  time.Duration(d.GetSessionAgeMs()) * time.Millisecond,
				LastRecvAge: time.Duration(d.GetLastRecvAgeMs()) * time.Millisecond,
				Attempts:    d.GetAttempts(),
				Ups:         d.GetUps(),
				Drops:       d.GetDrops(),
				Trace:       d.GetTrace(),
			}
		}
	}
	return st
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// doctorVersion names the CLI build in the report header. Build info carries
// the module version for a released binary, "(devel)" for a local build.
func doctorVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}
