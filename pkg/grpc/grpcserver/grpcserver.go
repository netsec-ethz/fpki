package grpcserver

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/netsec-ethz/fpki/pkg/db"
	pb "github.com/netsec-ethz/fpki/pkg/grpc/query"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50050, "The server port")
)

// ResponderServer: server to distribute map response
type ResponderServer struct {
	pb.UnimplementedMapResponderServer
	responder *responder.MapResponder
}

type GRPCProofs struct {
	Proofs []*common.MapServerResponse
}

// QueryMapEntries: return value according to key
func (server ResponderServer) QueryMapEntries(ctx context.Context, in *pb.MapClientRequest) (*pb.MapClientReply, error) {
	proofs, err := server.responder.GetProof(ctx, in.DomainName)
	if err != nil {
		return nil, err
	}

	result := GRPCProofs{Proofs: proofs}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("QueryMapEntries | Marshal | %w", err)
	}

	return &pb.MapClientReply{
		DomainName: in.GetDomainName(),
		Proof:      resultBytes,
	}, nil
}

func NewGRPCServer(
	ctx context.Context,
	conn db.Conn,
	privKey *rsa.PrivateKey,
) (*ResponderServer, error) {

	responder, err := responder.NewMapResponder(ctx, conn, privKey)
	if err != nil {
		return nil, err
	}

	return &ResponderServer{responder: responder}, nil
}

func (s *ResponderServer) Close() error {
	return nil
}

func (server *ResponderServer) StartWork(terminateChan chan byte, port int) error {
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	s := grpc.NewServer()

	pb.RegisterMapResponderServer(s, server)
	log.Printf("server listening at %v", lis.Addr())

	go s.Serve(lis)

	_ = <-terminateChan

	return nil
}
