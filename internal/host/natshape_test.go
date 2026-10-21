package host

// The pair's NAT shape, as a verdict a reader can act on: the two facts the
// engine observed (the peer answered from an endpoint it never announced, and
// the direct path is one-way) collapse into one word.
//
// It is a lookup, not a cascade: the two facts are independent, and the
// combination is a verdict of its own — a peer that answers from somewhere
// else AND a path that carries nothing is one failure, not two.

import (
	"testing"
)

// TestNatShape: the verdict's four combinations, pinned to exact words.
func TestNatShape(t *testing.T) {
	tests := []struct {
		name    string
		differs bool
		oneWay  bool
		want    string
	}{
		{
			name: "neither observed",
			want: "",
		},
		{
			name:    "the peer answers from an endpoint it did not announce",
			differs: true,
			want:    "peer-endpoint-differs",
		},
		{
			name:   "the direct path was one-way",
			oneWay: true,
			want:   "one-way",
		},
		{
			name:    "both",
			differs: true,
			oneWay:  true,
			want:    "one-way+peer-endpoint-differs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := natShape(tt.differs, tt.oneWay); got != tt.want {
				t.Fatalf("natShape(%v, %v) = %q, want %q", tt.differs, tt.oneWay, got, tt.want)
			}
		})
	}
}
