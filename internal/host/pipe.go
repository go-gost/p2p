package host

import "context"

// pipeStream is an in-memory Stream: a Send on one end is a Recv on the other,
// preserving chunk boundaries exactly as the gRPC transport does. Both ends
// share ctx; cancelling it ends both, mirroring "the RPC ending" on the gRPC
// path, so the same serveTunnel logic works over either carrier.
type pipeStream struct {
	ctx  context.Context
	send chan []byte
	recv chan []byte
}

func (p *pipeStream) Send(b []byte) error {
	// Copy the payload: the caller may reuse its buffer once Write returns
	// (io.Copy does), and unlike the gRPC path's synchronous marshal there is
	// nothing else here that copies before the chunk is queued.
	b = append([]byte(nil), b...)
	select {
	case p.send <- b:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *pipeStream) Recv() ([]byte, error) {
	select {
	case b := <-p.recv:
		return b, nil
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

func (p *pipeStream) Context() context.Context { return p.ctx }

// newPipePair returns the two ends of an in-memory tunnel stream. client's Send
// feeds server's Recv and vice versa; the names reflect which end Dial hands to
// the caller (client) and which the host serves (server).
func newPipePair(ctx context.Context) (client, server *pipeStream) {
	up := make(chan []byte, 8)
	down := make(chan []byte, 8)
	client = &pipeStream{ctx: ctx, send: up, recv: down}
	server = &pipeStream{ctx: ctx, send: down, recv: up}
	return client, server
}
