package main

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// startHubStub returns a throwaway UDP socket standing in for the hub's tun
// server, plus its "udp://" target spec.
func startHubStub(t *testing.T) (*net.UDPConn, string) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, "udp://" + conn.LocalAddr().String()
}

// TestEnableHubValidation: hub mode needs both a peer key and a udp target.
func TestEnableHubValidation(t *testing.T) {
	e := newTestEngine(t)
	_, keyA, _ := derpclient.Generate()

	if err := e.EnableHub(nil); err == nil {
		t.Fatal("EnableHub accepted an empty allowlist")
	}
	if err := e.addTargets([]string{"127.0.0.1:18080"}); err != nil { // tcp only
		t.Fatal(err)
	}
	if err := e.EnableHub([]derpclient.PublicKey{keyA}); err == nil {
		t.Fatal("EnableHub accepted a config with no udp target")
	}
}

// TestHubDeniedAndChannels: before hub mode nothing is denied; after it only
// allowlisted peers pass, and each allowed key owns a channel whose local edge
// is the datagram adapter. Engine.Close tears those edges down.
func TestHubDeniedAndChannels(t *testing.T) {
	e := newTestEngine(t)
	_, keyA, _ := derpclient.Generate()
	_, keyB, _ := derpclient.Generate()

	if e.hubDenied(keyA) {
		t.Fatal("hubDenied true before hub mode is enabled")
	}

	_, spec := startHubStub(t)
	if err := e.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableHub([]derpclient.PublicKey{keyA, keyB}); err != nil {
		t.Fatal(err)
	}

	for _, k := range []derpclient.PublicKey{keyA, keyB} {
		if e.hubDenied(k) {
			t.Fatalf("allowed peer %s denied", keyName(k))
		}
	}
	if _, keyC, _ := derpclient.Generate(); !e.hubDenied(keyC) {
		t.Fatal("non-allowlisted peer allowed")
	}

	var edges []*dgramEdge
	for _, k := range []derpclient.PublicKey{keyA, keyB} {
		ch := e.channel(k)
		if ch == nil {
			t.Fatalf("no channel for allowed peer %s", keyName(k))
		}
		ch.mu.Lock()
		edge, _ := ch.local.(*dgramEdge)
		ch.mu.Unlock()
		if edge == nil {
			t.Fatalf("hub channel for %s has no datagram edge", keyName(k))
		}
		edges = append(edges, edge)
	}

	e.Close()
	for _, edge := range edges {
		if _, err := edge.Write(appendFrame(nil, []byte("x"))); err == nil {
			t.Fatal("edge still writable after Engine.Close")
		}
	}
}

// TestHubChannelRoundTrip drives both directions through a hub channel: the
// spoke's framed bytes become one UDP datagram at the tun-server stub, and a
// datagram from the stub comes back to the spoke as framed bytes.
func TestHubChannelRoundTrip(t *testing.T) {
	rs := &relayServer{}
	url := rs.start(t)

	// The spoke must own the smaller key so it dials the channel to the hub
	// (whose channel EnableHub prebuilds).
	var privH, privS derpclient.PrivateKey
	var pubH, pubS derpclient.PublicKey
	for {
		privH, pubH, _ = derpclient.Generate()
		privS, pubS, _ = derpclient.Generate()
		if bytes.Compare(pubS[:], pubH[:]) < 0 {
			break
		}
	}

	hub := newEngine(url, "", privH, slog.Default())
	spoke := newEngine(url, "", privS, slog.Default())
	defer hub.Close()
	defer spoke.Close()
	if err := hub.Connect(); err != nil {
		t.Fatal(err)
	}
	if err := spoke.Connect(); err != nil {
		t.Fatal(err)
	}

	stub, spec := startHubStub(t)
	if err := hub.addTargets([]string{spec}); err != nil {
		t.Fatal(err)
	}
	if err := hub.EnableHub([]derpclient.PublicKey{pubS}); err != nil {
		t.Fatal(err)
	}

	chS := spoke.openChannel(pubH) // opener: dials the channel to the hub
	defer chS.release()
	localS := attachLocal(t, chS)

	waitStream(t, chS)
	chH := hub.channel(pubS)
	if chH == nil {
		t.Fatal("hub has no channel for the spoke")
	}
	waitStream(t, chH)
	chH.mu.Lock()
	edge, _ := chH.local.(*dgramEdge)
	chH.mu.Unlock()
	if edge == nil {
		t.Fatal("hub channel has no datagram edge")
	}

	// Spoke -> hub -> stub: framed bytes on the spoke's local edge reach the
	// stub as one datagram.
	go localS.Write(appendFrame(nil, []byte("hello")))
	got, err := recvDatagram(t, stub)
	if err != nil {
		t.Fatalf("stub received nothing: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("datagram = %q, want hello", got)
	}

	// Stub -> hub -> spoke: a datagram comes back framed.
	if _, err := stub.WriteToUDP([]byte("world"), edge.conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	want := appendFrame(nil, []byte("world"))
	if got := readN(t, localS, len(want)); !bytes.Equal(got, want) {
		t.Fatalf("spoke local got %x, want %x", got, want)
	}
}

// startTCPCounter listens on tcp and counts accepted connections, so a test can
// prove a stream was (or was not) bridged.
func startTCPCounter(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	return ln.Addr().String(), &n
}

func waitAccepted(t *testing.T, n *atomic.Int32, want int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("tcp target accepted %d, want %d", n.Load(), want)
}

// TestServeInboundHubGuard: with hub mode on, a stream from a peer that is not
// on the allowlist is refused before any classification — so an untagged
// stream is not bridged to the tcp target (fail-closed covers both kinds) —
// while an allowlisted peer's stream is bridged as usual.
func TestServeInboundHubGuard(t *testing.T) {
	e := newTestEngine(t)
	_, keyAllowed, _ := derpclient.Generate()
	_, keyOther, _ := derpclient.Generate()

	_, udpSpec := startHubStub(t)
	tcpAddr, accepted := startTCPCounter(t)
	if err := e.addTargets([]string{udpSpec, tcpAddr}); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableHub([]derpclient.PublicKey{keyAllowed}); err != nil {
		t.Fatal(err)
	}

	// Non-allowlisted peer: refused, and no tcp dial results.
	server, client := net.Pipe()
	e.serveInbound(server, "derp", keyOther, "")
	client.Close()
	if n := accepted.Load(); n != 0 {
		t.Fatalf("refused peer caused %d tcp dial(s), want 0", n)
	}

	// Allowlisted peer: an untagged stream is bridged to the tcp target.
	server2, client2 := net.Pipe()
	go func() {
		client2.Write([]byte("ping")) // completes the tag peek as untagged
		io.Copy(io.Discard, client2)
	}()
	go e.serveInbound(server2, "derp", keyAllowed, "")
	waitAccepted(t, accepted, 1)
	client2.Close()
}
