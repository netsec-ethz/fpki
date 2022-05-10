package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	pb "github.com/netsec-ethz/fpki/pkg/grpc/query"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	domainName = "world"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
	name = flag.String("name", domainName, "Domain name to query")
)

func main() {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewMapResponderClient(conn)

	start := time.Now()
	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	for i := 0; i < 10000; i++ {
		_, err = c.QueryMapEntries(ctx, &pb.MapClientRequest{DomainName: *name})
		if err != nil {
			log.Fatalf("could not greet: %v", err)
		}
	}
	//log.Printf("proof size: %d", len(r.GetProof()))
	//log.Printf("domain name: %s", r.DomainName)
	//fmt.Println("proof ", r.GetProof())
	//log.Printf("proof type: %s", r.ProofType)
	end := time.Now()
	fmt.Println(end.Sub(start))
}
