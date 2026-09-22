package grpc

import (
	"context"
	"crypto/subtle"

	ggrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// authInterceptor returns a unary interceptor comparing the client's token
// metadata against want. Constant-time compare; an absent token never matches.
func authInterceptor(want string) ggrpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *ggrpc.UnaryServerInfo, handler ggrpc.UnaryHandler) (any, error) {
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
func streamAuthInterceptor(want string) ggrpc.StreamServerInterceptor {
	return func(srv any, ss ggrpc.ServerStream, info *ggrpc.StreamServerInfo, handler ggrpc.StreamHandler) error {
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
