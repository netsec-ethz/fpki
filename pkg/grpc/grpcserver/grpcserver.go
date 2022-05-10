package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	pb "github.com/netsec-ethz/fpki/pkg/grpc/query"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

// ResponderServer: server to distribute map response
type ResponderServer struct {
	pb.UnimplementedMapResponderServer
	result map[string][]byte
}

// QueryMapEntries: return value according to key
func (server ResponderServer) QueryMapEntries(ctx context.Context, in *pb.MapClientRequest) (*pb.MapClientReply, error) {
	//log.Printf("Received: %v", in.GetDomainName())

	var material []byte
	for _, v := range server.result {
		material = append(material, v...)
	}

	//fmt.Println(material)

	return &pb.MapClientReply{
		DomainName: in.GetDomainName(),
		Materials:  material,
		Proof:      material,
		ProofType:  pb.ProofType_PoA,
	}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	responderServer := &ResponderServer{
		result: make(map[string][]byte),
	}
	responderServer.result["hi"] = []byte{1, 3, 5, 6}

	pb.RegisterMapResponderServer(s, responderServer)
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
