package p2p

import (
	"context"

	"github.com/go-gost/plugin/p2p/proto"
)

// pipeStream is an in-memory tunnelStream: a Send on one end is a Recv on the
// other, preserving proto.Chunk boundaries exactly as the gRPC stream does.
// Both ends share ctx; cancelling it ends both, mirroring "the RPC ending" on
// the gRPC path, so the same serveTunnel logic works over either transport.
type pipeStream struct {
	ctx  context.Context
	send chan *proto.Chunk
	recv chan *proto.Chunk
}

func (p *pipeStream) Send(c *proto.Chunk) error {
	// Copy the payload: the caller may reuse its buffer once Write returns
	// (io.Copy does), and unlike the gRPC path's synchronous marshal there is
	// nothing else here that copies before the chunk is queued.
	c = &proto.Chunk{Data: append([]byte(nil), c.GetData()...)}
	select {
	case p.send <- c:
		return nil
	case <-p.ctx.Done():
		return p.ctx.Err()
	}
}

func (p *pipeStream) Recv() (*proto.Chunk, error) {
	select {
	case c := <-p.recv:
		return c, nil
	case <-p.ctx.Done():
		return nil, p.ctx.Err()
	}
}

func (p *pipeStream) Context() context.Context { return p.ctx }

// newPipePair returns the two ends of an in-memory tunnel stream. client's Send
// feeds server's Recv and vice versa; the names reflect which end the in-process
// Tunnel hands to the caller (client) and which the host serves (server).
func newPipePair(ctx context.Context) (client, server *pipeStream) {
	up := make(chan *proto.Chunk, 8)
	down := make(chan *proto.Chunk, 8)
	client = &pipeStream{ctx: ctx, send: up, recv: down}
	server = &pipeStream{ctx: ctx, send: down, recv: up}
	return client, server
}
