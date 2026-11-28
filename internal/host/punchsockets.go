package host

import (
	"net"
	"net/netip"
	"time"
)

// socketStartDelay caps the wait before the sockets side starts sending, so a
// spraying peer gets a head start. Tests shorten it.
var socketStartDelay = 2 * time.Second

type socketAttempt struct {
	sock *net.UDPConn
	out  seedOutcome
	err  error
}

// punchSockets runs the seed handshake from first and sockets-1 additional
// IPv4 sockets, all aimed at the peer's announced endpoint. Behind a symmetric
// NAT each local socket gets its own public mapping, so the peer only has to
// hit one of them. The first success wins; its socket is returned to the caller
// (which hands it to markUp) and every other socket is closed before returning.
// On a failed round every socket, including first, is closed.
func (dc *directConn) punchSockets(first *net.UDPConn, peer netip.AddrPort) (*net.UDPConn, seedOutcome, error) {
	if first == nil {
		return nil, seedOutcome{}, nil
	}
	e := dc.e
	n := e.punch.sockets
	if n < 1 {
		n = 1
	}
	socks := make([]*net.UDPConn, 0, n)
	socks = append(socks, first)
	for i := 1; i < n; i++ {
		sock, err := net.ListenUDP("udp4", bindAddrFor(e.stunAddr))
		if err != nil {
			for _, opened := range socks {
				opened.Close()
			}
			return nil, seedOutcome{}, err
		}
		socks = append(socks, sock)
	}

	delay := e.punch.sprayEvery
	if delay > socketStartDelay {
		delay = socketStartDelay
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	e.log.Debug("direct punch: sockets", "peer", keyName(dc.peer), "sockets", n, "delay", delay)

	plan := seedPlan{
		Peer:       peer,
		Retransmit: seedRetransmit,
		Grace:      e.punch.seedGrace,
	}
	results := make(chan socketAttempt, n)
	for _, sock := range socks {
		go func(sock *net.UDPConn) {
			out, err := seedHandshakePlan(sock, plan, e.punch.socketWindow)
			results <- socketAttempt{sock: sock, out: out, err: err}
		}(sock)
	}

	var win *net.UDPConn
	var winOut, failOut seedOutcome
	var firstErr error
	received := 0
	for received < n && win == nil {
		res := <-results
		received++
		if res.err == nil {
			win, winOut = res.sock, res.out
			continue
		}
		if firstErr == nil {
			firstErr, failOut = res.err, res.out
		}
	}
	// Closing a loser interrupts its read, so its goroutine reports and exits
	// before this function returns. The winner stays open for markUp.
	for _, sock := range socks {
		if sock != win {
			sock.Close()
		}
	}
	for ; received < n; received++ {
		<-results
	}
	if win == nil {
		e.log.Debug("direct punch: sockets failed", "peer", keyName(dc.peer), "error", firstErr)
		return nil, failOut, firstErr
	}
	e.log.Debug("direct punch: sockets up", "peer", keyName(dc.peer), "answer", winOut.Answer.String())
	return win, winOut, nil
}
