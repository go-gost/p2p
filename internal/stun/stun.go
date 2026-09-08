// Package stun implements the minimal client side of STUN (RFC 5389): a
// single binding request, enough to learn the public NAT mapping of a UDP
// socket for UDP hole punching.
package stun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/netip"
	"time"
)

const (
	magicCookie       = 0x2112A442
	bindingRequest    = 0x0001
	bindingSuccess    = 0x0101
	attrXorMappedAddr = 0x0020
	headerLen         = 20
)

// Tailscale's derper STUN server only answers its own dialect of binding
// request: it requires a SOFTWARE attribute with value "tailnode" and a
// trailing FINGERPRINT attribute (RFC 5389 §15.5), rejecting plain requests.
const (
	attrSoftware    = 0x8022
	attrFingerprint = 0x8028
	software        = "tailnode"
	fpXor           = 0x5354554e
)

// Lookup sends a binding request from conn to the STUN server at addr and
// returns the socket's public address (XOR-MAPPED-ADDRESS). conn must be the
// exact socket that will later be used for punching, so the reported mapping
// matches the one the peer will reach.
func Lookup(ctx context.Context, addr string, conn *net.UDPConn) (netip.AddrPort, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}

	var txn [12]byte
	if _, err := rand.Read(txn[:]); err != nil {
		return netip.AddrPort{}, err
	}
	req := bindingRequestBytes(txn)

	if _, err := conn.WriteToUDP(req, raddr); err != nil {
		return netip.AddrPort{}, err
	}

	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	conn.SetReadDeadline(deadline)
	defer conn.SetReadDeadline(time.Time{}) // hand the socket back to KCP clean

	buf := make([]byte, 1500)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return netip.AddrPort{}, err
		}
		if src.String() != raddr.String() {
			continue // ignore datagrams from anyone but the STUN server
		}
		if n < headerLen {
			continue
		}
		pkt := buf[:n]
		if binary.BigEndian.Uint32(pkt[4:8]) != magicCookie {
			continue
		}
		if !bytes.Equal(pkt[8:20], txn[:]) {
			continue // transaction ID mismatch
		}
		if binary.BigEndian.Uint16(pkt[0:2]) != bindingSuccess {
			return netip.AddrPort{}, errors.New("stun: non-success binding response")
		}
		return parseXorMapped(pkt[headerLen:], txn)
	}
}

// bindingRequestBytes builds a Tailscale-dialect binding request: header,
// SOFTWARE="tailnode", then a FINGERPRINT over everything so far.
func bindingRequestBytes(txn [12]byte) []byte {
	const attrLen = (4 + len(software)) + (4 + 4) // SOFTWARE + FINGERPRINT
	b := make([]byte, 0, headerLen+attrLen)
	b = appendU16(b, bindingRequest)
	b = appendU16(b, uint16(attrLen))
	b = appendU32(b, magicCookie)
	b = append(b, txn[:]...)
	b = appendU16(b, attrSoftware)
	b = appendU16(b, uint16(len(software)))
	b = append(b, software...)
	fp := crc32.ChecksumIEEE(b) ^ fpXor
	b = appendU16(b, attrFingerprint)
	b = appendU16(b, 4)
	return appendU32(b, fp)
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func parseXorMapped(attrs []byte, txn [12]byte) (netip.AddrPort, error) {
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		ln := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+ln > len(attrs) {
			return netip.AddrPort{}, errors.New("stun: short attribute")
		}
		if typ == attrXorMappedAddr {
			return decodeXorMapped(attrs[4:4+ln], txn)
		}
		attrs = attrs[4+((ln+3)&^3):] // attributes are 4-byte aligned
	}
	return netip.AddrPort{}, errors.New("stun: no XOR-MAPPED-ADDRESS")
}

func decodeXorMapped(v []byte, txn [12]byte) (netip.AddrPort, error) {
	if len(v) < 4 {
		return netip.AddrPort{}, errors.New("stun: short xor-mapped-address")
	}
	xport := binary.BigEndian.Uint16(v[2:4]) ^ uint16(magicCookie>>16)
	switch v[1] { // address family
	case 0x01: // IPv4
		if len(v) < 8 {
			return netip.AddrPort{}, errors.New("stun: short ipv4 xor-mapped-address")
		}
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(v[4:8])^magicCookie)
		return netip.AddrPortFrom(netip.AddrFrom4(ip), xport), nil
	case 0x02: // IPv6 (RFC 5389): first 4 bytes xor the magic cookie, the rest xor the txn.
		if len(v) < 20 {
			return netip.AddrPort{}, errors.New("stun: short ipv6 xor-mapped-address")
		}
		var ip [16]byte
		copy(ip[:], v[4:20])
		binary.BigEndian.PutUint32(ip[:4], binary.BigEndian.Uint32(ip[:4])^magicCookie)
		for i := 4; i < len(ip); i++ {
			ip[i] ^= txn[i-4]
		}
		addr := netip.AddrFrom16(ip)
		if addr.Is4In6() {
			// A dual-stack STUN server reports an IPv4 source as an IPv4-mapped
			// IPv6 address (::ffff:a.b.c.d). Unmap so the IPv4 punching socket
			// can use it.
			addr = addr.Unmap()
		}
		return netip.AddrPortFrom(addr, xport), nil
	default:
		return netip.AddrPort{}, errors.New("stun: unsupported address family")
	}
}
