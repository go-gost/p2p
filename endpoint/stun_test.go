package endpoint

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestStunLookup probes a fake STUN server on loopback: the returned address
// must be the mapping the server reports for the probe's own socket.
func TestStunLookup(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	seen := make(chan *net.UDPAddr, 1)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, src, err := srv.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 20 || binary.BigEndian.Uint16(buf[0:2]) != 0x0001 {
				continue // not a binding request
			}
			select {
			case seen <- src:
			default:
			}
			if _, err := srv.WriteToUDP(xorMappedResponse(buf[:n], src), src); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := StunLookup(ctx, srv.LocalAddr().String())
	if err != nil {
		t.Fatalf("StunLookup: %v", err)
	}

	var src *net.UDPAddr
	select {
	case src = <-seen:
	case <-time.After(time.Second):
		t.Fatal("the STUN server saw no binding request")
	}
	ip4 := src.IP.To4()
	if ip4 == nil {
		t.Fatalf("probe source %v is not IPv4", src)
	}
	want := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ip4)), uint16(src.Port))
	if got != want {
		t.Fatalf("StunLookup = %v, want the server's view %v", got, want)
	}

	// A server that never answers must fail rather than hang.
	dead, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.LocalAddr().String()
	dead.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()
	if _, err := StunLookup(ctx2, addr); err == nil {
		t.Fatal("StunLookup of a silent server returned an address")
	}
}

// xorMappedResponse answers a binding request with the sender's own address
// (the shape the client parses: header, XOR-MAPPED-ADDRESS, echoed transaction).
func xorMappedResponse(req []byte, src *net.UDPAddr) []byte {
	const magic = 0x2112A442
	ip4 := src.IP.To4()

	resp := make([]byte, 20, 32)
	binary.BigEndian.PutUint16(resp[0:2], 0x0101) // binding success
	binary.BigEndian.PutUint16(resp[2:4], 12)     // attribute length
	binary.BigEndian.PutUint32(resp[4:8], magic)
	copy(resp[8:20], req[8:20]) // transaction id

	v := make([]byte, 8)
	v[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(v[2:4], uint16(src.Port)^uint16(magic>>16))
	binary.BigEndian.PutUint32(v[4:8], binary.BigEndian.Uint32(ip4)^magic)

	resp = append(resp, 0x00, 0x20, 0x00, 0x08) // XOR-MAPPED-ADDRESS, 8 bytes
	return append(resp, v...)
}
