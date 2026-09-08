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

// startResponderV6Mapped runs an in-process STUN server that answers like a
// dual-stack server would for an IPv4 client: it reports the source as an
// IPv4-mapped IPv6 address under address family 0x02 (the case that bit the
// real derper on an IPv6-enabled host).
func startResponderV6Mapped(t *testing.T) string {
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
			conn.WriteToUDP(makeResponseV6Mapped(req, addr), addr)
		}
	}()
	return conn.LocalAddr().String()
}

func makeResponseV6Mapped(req []byte, addr *net.UDPAddr) []byte {
	resp := make([]byte, 0, headerLen+28)
	resp = append(resp, 0x01, 0x01)   // binding success
	resp = append(resp, 0x00, 0x18)   // length: one 24-byte attribute (4+20)
	resp = append(resp, req[4:20]...) // cookie + transaction ID
	resp = append(resp, 0x00, 0x20)   // XOR-MAPPED-ADDRESS type
	resp = append(resp, 0x00, 0x14)   // attribute length
	resp = append(resp, 0x00)         // reserved
	resp = append(resp, 0x02)         // family: IPv6
	xport := uint16(addr.Port) ^ uint16(magicCookie>>16)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], xport)
	resp = append(resp, pb[:]...)
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	ip4 := addr.IP.To4()
	// 16-byte IPv4-mapped form, then xor: first 4 bytes with the magic cookie,
	// the remaining 12 with the transaction ID.
	ip := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, ip4[0], ip4[1], ip4[2], ip4[3]}
	for i := 0; i < 4; i++ {
		ip[i] ^= cookie[i]
	}
	for i := 4; i < 16; i++ {
		ip[i] ^= req[8+i-4]
	}
	resp = append(resp, ip[:]...)
	return resp
}

func TestLookupV6Mapped(t *testing.T) {
	srv := startResponderV6Mapped(t)

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
	if !got.Addr().Is4() {
		t.Fatalf("mapped addr = %s, want unmapped IPv4", got.Addr())
	}
	want := sock.LocalAddr().(*net.UDPAddr)
	if got.Addr().As4() != [4]byte(want.IP.To4()) {
		t.Fatalf("mapped addr = %s, want %s", got.Addr(), want.IP)
	}
	if got.Port() != uint16(want.Port) {
		t.Fatalf("mapped port = %d, want %d", got.Port(), want.Port)
	}
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
