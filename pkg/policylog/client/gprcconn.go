package client

import (
	"fmt"

	"github.com/google/trillian/client/rpcflags"
	"google.golang.org/grpc"
)

// get a GRPC connection to the log server; will be used later for log client
func getGRPCConn(maxReceiveMessageSize int, logAddress string) (*grpc.ClientConn, error) {
	// get security flag
	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	if err != nil {
		return nil, fmt.Errorf("GetGRPCConn | NewClientDialOptionsFromFlags | %w", err)
	}

	// add max_receive_msg flag
	if maxReceiveMessageSize > 0 {
		dialOpts = append(dialOpts, grpc.WithMaxMsgSize(maxReceiveMessageSize))
	}

	// dial the grpc
	conn, err := grpc.Dial(logAddress, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("GetGRPCConn | Dial | %w", err)
	}
	return conn, nil
}
