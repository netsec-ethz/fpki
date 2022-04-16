package PL_LogClient

import (
	"fmt"
	"github.com/google/trillian/client/rpcflags"
	"google.golang.org/grpc"
)

func GetGRPCConn(maxReceiveMessageSize int, logAddress string) (*grpc.ClientConn, error) {
	// get security flag
	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	if err != nil {
		return nil, fmt.Errorf("GetGRPCConn | NewClientDialOptionsFromFlags | %s", err.Error())
	}

	// add max_receive_msg flag
	if maxReceiveMessageSize > 0 {
		dialOpts = append(dialOpts, grpc.WithMaxMsgSize(maxReceiveMessageSize))
	}

	// dial the grpc
	conn, err := grpc.Dial(logAddress, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("GetGRPCConn | Dial | %s", err.Error())
	}

	return conn, nil
}
