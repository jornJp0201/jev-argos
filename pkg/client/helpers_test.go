package client

import (
	"context"
	"net"

	"google.golang.org/grpc/peer"
)

func peerCtx(addr string) context.Context {
	a, _ := net.ResolveTCPAddr("tcp", addr)
	return peer.NewContext(context.Background(), &peer.Peer{Addr: a})
}
