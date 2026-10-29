package host

import (
	"bytes"
	"errors"
	"testing"
)

func TestCapsEncodeLegacy(t *testing.T) {
	if got := encodeCaps(capsInfo{Bits: capsIPv6}); !bytes.Equal(got, []byte{capsIPv6}) {
		t.Fatalf("legacy caps = % x", got)
	}
}

func TestCapsRoundTripQUIC(t *testing.T) {
	fp := [32]byte{1, 2, 3}
	in := capsInfo{Bits: capsIPv6 | capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: fp, BatchVersion: 1}}
	out, err := decodeCaps(encodeCaps(in))
	if err != nil || out.Bits != in.Bits || out.QUIC == nil || out.QUIC.Fingerprint != fp {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	if out.QUIC.Version != in.QUIC.Version || out.QUIC.BatchVersion != in.QUIC.BatchVersion {
		t.Fatalf("round trip versions: %+v", out.QUIC)
	}
}

func TestCapsEncodeLayout(t *testing.T) {
	fp := [32]byte{0xAA}
	got := encodeCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 2, Fingerprint: fp, BatchVersion: 3}})
	want := []byte{capsQUIC, capsTLVVersion1, capsTLVQUIC, 34, 2}
	want = append(want, fp[:]...)
	want = append(want, 3)
	if !bytes.Equal(got, want) {
		t.Fatalf("caps = % x, want % x", got, want)
	}
}

func TestCapsDecodeEmpty(t *testing.T) {
	if _, err := decodeCaps(nil); err == nil {
		t.Fatal("empty caps decoded without error")
	}
}

func TestCapsDecodeLegacy(t *testing.T) {
	info, err := decodeCaps([]byte{capsIPv6 | capsNoDirect})
	if err != nil {
		t.Fatal(err)
	}
	if info.Bits != capsIPv6|capsNoDirect || info.QUIC != nil {
		t.Fatalf("legacy caps = %+v", info)
	}
}

func TestCapsDecodeUnknownTLV(t *testing.T) {
	// Two unknown, well-formed TLVs: both are skipped.
	info, err := decodeCaps([]byte{capsIPv6, capsTLVVersion1, 0x7f, 0, 0, 0})
	if err != nil {
		t.Fatalf("unknown TLV: %v", err)
	}
	if info.Bits != capsIPv6 || info.QUIC != nil {
		t.Fatalf("unknown TLV caps = %+v", info)
	}
}

func TestCapsDecodeMalformedTLV(t *testing.T) {
	cases := map[string][]byte{
		"truncated header": {capsQUIC, capsTLVVersion1, capsTLVQUIC},
		"truncated value":  {capsQUIC, capsTLVVersion1, capsTLVQUIC, 34, 1},
		"short quic value": {capsQUIC, capsTLVVersion1, capsTLVQUIC, 33},
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			info, err := decodeCaps(b)
			if err == nil {
				t.Fatal("malformed TLV decoded without error")
			}
			if info.Bits != capsQUIC {
				t.Fatalf("bits = %#x, want %#x", info.Bits, capsQUIC)
			}
			if info.QUIC != nil {
				t.Fatalf("QUIC = %+v, want nil on malformed TLV", info.QUIC)
			}
		})
	}
}

func TestCapsDecodeUnknownVersion(t *testing.T) {
	info, err := decodeCaps([]byte{capsQUIC | capsIPv6, capsTLVVersion1 + 1, capsTLVQUIC, 34})
	if !errors.Is(err, errUnsupportedCapsVersion) {
		t.Fatalf("err = %v, want errUnsupportedCapsVersion", err)
	}
	if info.Bits != capsQUIC|capsIPv6 || info.QUIC != nil {
		t.Fatalf("unknown version caps = %+v", info)
	}
}

func TestCapsDecodeRepeatedQUICLatestWins(t *testing.T) {
	first, second := [32]byte{1}, [32]byte{2}
	b := []byte{capsQUIC, capsTLVVersion1, capsTLVQUIC, 34, 1}
	b = append(b, first[:]...)
	b = append(b, 1, capsTLVQUIC, 34, 1)
	b = append(b, second[:]...)
	b = append(b, 2)
	info, err := decodeCaps(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.QUIC == nil || info.QUIC.Fingerprint != second || info.QUIC.BatchVersion != 2 {
		t.Fatalf("repeated QUIC TLV = %+v, want the last", info.QUIC)
	}
}

func TestCapsQUICLatestFingerprintWins(t *testing.T) {
	dc := &directConn{}
	dc.addCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{1}}})
	dc.addCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{2}}})
	got, ok := dc.peerQUICInfo()
	if !ok || got.Fingerprint != [32]byte{2} {
		t.Fatalf("got %+v ok=%v", got, ok)
	}
}

func TestCapsQUICBitWithoutTLVClearsInfo(t *testing.T) {
	dc := &directConn{e: newTestEngine(t)}
	dc.addCaps(capsInfo{Bits: capsQUIC | capsIPv6, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{1}}})
	if _, ok := dc.peerQUICInfo(); !ok {
		t.Fatal("QUIC info not recorded")
	}
	// The bit alone is a claim without parameters: nothing to use.
	dc.addCaps(capsInfo{Bits: capsQUIC | capsIPv6})
	if _, ok := dc.peerQUICInfo(); ok {
		t.Fatal("QUIC info kept after a caps frame without the TLV")
	}
	if dc.peerCaps&capsQUIC == 0 {
		t.Fatalf("peerCaps = %#x, want the sticky QUIC bit kept", dc.peerCaps)
	}
	// A frame without the bit drops the parameters even though bits are sticky.
	dc.addCaps(capsInfo{Bits: capsQUIC, QUIC: &quicCaps{Version: 1, Fingerprint: [32]byte{2}}})
	dc.addCaps(capsInfo{Bits: capsIPv6})
	if _, ok := dc.peerQUICInfo(); ok {
		t.Fatal("QUIC info kept after a caps frame without the QUIC bit")
	}
}
