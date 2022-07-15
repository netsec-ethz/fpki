package grpcclient

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strconv"
	"time"

	"github.com/netsec-ethz/fpki/pkg/grpc/grpcserver"
	pb "github.com/netsec-ethz/fpki/pkg/grpc/query"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	domainName = "world"
)

var (
	addr = flag.String("addr", "localhost:", "the address to connect to")
	name = flag.String("name", domainName, "Domain name to query")
)

func GetProofs(name string, port int) ([]common.MapServerResponse, error) {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial("localhost:"+strconv.Itoa(port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	defer conn.Close()
	c := pb.NewMapResponderClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()

	proofs, err := c.QueryMapEntries(ctx, &pb.MapClientRequest{DomainName: name})
	if err != nil {
		return nil, err
	}

	result := &grpcserver.GRPCProofs{}

	err = json.Unmarshal(proofs.Proof, result)
	if err != nil {
		return nil, fmt.Errorf("GetProofs | Unmarshal | %w", err)
	}

	return result.Proofs, nil
}
