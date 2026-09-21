package p2p

import (
	"context"
	"crypto/subtle"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authInterceptor returns a unary interceptor comparing the client's token
// metadata against want. Constant-time compare; an absent token never matches.
func authInterceptor(want string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if want != "" {
			got := ""
			if md, ok := metadata.FromIncomingContext(ctx); ok && len(md["token"]) > 0 {
				got = md["token"][0]
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return nil, status.Error(codes.Unauthenticated, "invalid token")
			}
		}
		return handler(ctx, req)
	}
}

// streamAuthInterceptor is the stream-RPC counterpart of authInterceptor
// (Tunnel). The stream's actual credential is its unguessable id, checked by
// the handler; this token check is defense in depth and costs nothing — the
// GOST client's per-RPC credentials already attach the token to every RPC,
// streams included.
func streamAuthInterceptor(want string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if want != "" {
			got := ""
			if md, ok := metadata.FromIncomingContext(ss.Context()); ok && len(md["token"]) > 0 {
				got = md["token"][0]
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				return status.Error(codes.Unauthenticated, "invalid token")
			}
		}
		return handler(srv, ss)
	}
}
