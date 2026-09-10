//go:build !linux

package main

import (
	"errors"
	"io"
)

// openDevice is unimplemented off Linux: only the Linux tun/tap path exists so
// far (macOS utun and Windows wintun differ). The pump and framing above are
// platform-independent.
func openDevice(name string, kind deviceKind) (io.ReadWriteCloser, error) {
	return nil, errors.New("device link (--link) requires Linux")
}
