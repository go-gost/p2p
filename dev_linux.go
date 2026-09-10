//go:build linux

package main

import (
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openDevice attaches to an existing tun/tap interface by name. It does not
// create or configure the interface — addresses, routes, MTU and admin-up are
// the caller's job — it only opens the character device. IFF_NO_PI omits the
// 4-byte packet-info prefix so reads/writes are bare frames/packets.
//
// The device must be free: a tun is exclusive-open, so a device already held by
// another process (e.g. a gost tun listener) fails with EBUSY.
func openDevice(name string, kind deviceKind) (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	flags := unix.IFF_TUN
	if kind == deviceTap {
		flags = unix.IFF_TAP
	}
	ifr.SetUint16(uint16(flags | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}
