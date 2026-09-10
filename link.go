package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/go-gost/p2p/internal/derpclient"
)

// parseLink parses a --link spec "device=peer-key", where device is "name",
// "tun:name", or "tap:name" (default tun). A ":" whose prefix is not tun/tap is
// treated as part of the device name.
func parseLink(spec string) (name string, kind deviceKind, peer string, err error) {
	left, peer, ok := strings.Cut(spec, "=")
	if !ok || left == "" || peer == "" {
		return "", 0, "", fmt.Errorf("want \"device=peer-key\", got %q", spec)
	}
	kind, name = deviceTun, left
	if t, n, ok := strings.Cut(left, ":"); ok && n != "" {
		switch t {
		case "tun":
			kind, name = deviceTun, n
		case "tap":
			kind, name = deviceTap, n
		}
	}
	return name, kind, peer, nil
}

// addLink starts the device link to peer. The role is fixed by public-key
// ordering — the same rule as the mux session and the punch conv — so both ends
// converge on exactly one stream: the smaller key opens it and bridges its
// device to it; the larger key opens nothing and is served by acceptLoop, which
// routes the inbound stream to the device.
func (e *Engine) addLink(peerB64 string) error {
	peer, err := parsePeerKey(peerB64)
	if err != nil {
		return err
	}
	if e.dev == nil {
		return fmt.Errorf("device link: no device")
	}
	if bytes.Compare(e.pub[:], peer[:]) < 0 {
		e.log.Info("device link role", "peer", keyName(peer), "role", "opener")
		go e.linkLoop(peer)
	} else {
		e.log.Info("device link role", "peer", keyName(peer), "role", "responder")
	}
	return nil
}

// linkLoop keeps exactly one device-link stream to peer alive: open, bridge the
// device to it until it dies, back off, repeat. Retries do not need the relay up
// (OpenStream redials on demand). Packets read from the device while no stream
// is up are dropped by devReadLoop.
func (e *Engine) linkLoop(peer derpclient.PublicKey) {
	pname := keyName(peer)
	for {
		c, err := e.OpenStream(pname)
		if err != nil {
			e.log.Debug("device link: open stream", "peer", pname, "error", err)
		} else {
			transport := ""
			if tw, ok := c.(interface{ Transport() string }); ok {
				transport = tw.Transport()
			}
			e.log.Info("device link up", "peer", pname, "transport", transport)
			e.serveLink(c)
			e.log.Info("device link down", "peer", pname)
		}
		select {
		case <-e.stop:
			return
		case <-time.After(backoffPeriod):
		}
	}
}
