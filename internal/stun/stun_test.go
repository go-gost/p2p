package stun

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// startResponder runs an in-process STUN server that answers binding requests
// with an XOR-MAPPED-ADDRESS reflecting the sender's source address.
func startResponder(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			req := buf[:n]
			if n < headerLen || binary.BigEndian.Uint16(req[0:2]) != bindingRequest {
				continue
			}
			resp := makeResponse(req, addr)
			conn.WriteToUDP(resp, addr)
		}
	}()
	return conn.LocalAddr().String()
}

func makeResponse(req []byte, addr *net.UDPAddr) []byte {
	resp := make([]byte, 0, headerLen+12)
	resp = append(resp, 0x01, 0x01)   // binding success
	resp = append(resp, 0x00, 0x0c)   // length: one 8-byte attribute (4+8)
	resp = append(resp, req[4:20]...) // cookie + transaction ID
	resp = append(resp, 0x00, 0x20)   // XOR-MAPPED-ADDRESS type
	resp = append(resp, 0x00, 0x08)   // attribute length
	resp = append(resp, 0x00)         // reserved
	resp = append(resp, 0x01)         // family: IPv4
	xport := uint16(addr.Port) ^ uint16(magicCookie>>16)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], xport)
	resp = append(resp, pb[:]...)
	var xaddr [4]byte
	ip := addr.IP.To4()
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	for i := 0; i < 4; i++ {
		xaddr[i] = ip[i] ^ cookie[i]
	}
	resp = append(resp, xaddr[:]...)
	return resp
}

func TestLookup(t *testing.T) {
	srv := startResponder(t)

	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := Lookup(ctx, srv, sock)
	if err != nil {
		t.Fatal(err)
	}
	want := sock.LocalAddr().(*net.UDPAddr)
	if got.Addr().As4() != [4]byte(want.IP.To4()) {
		t.Fatalf("mapped addr = %s, want %s", got.Addr(), want.IP)
	}
	if got.Port() != uint16(want.Port) {
		t.Fatalf("mapped port = %d, want %d", got.Port(), want.Port)
	}
}

func TestLookupUnreachable(t *testing.T) {
	sock, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sock.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// A UDP port with no listener: the request goes nowhere.
	if _, err := Lookup(ctx, "127.0.0.1:1", sock); err == nil {
		t.Fatal("expected timeout error from unreachable STUN server")
	}
}
