package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/trillian"
	trillianClient "github.com/google/trillian/client"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	"io/ioutil"
	"strconv"
	"time"
)

// admin client is mainly used for managing trees;
// For example, create tree, list trees or delete tree

// TODO: termination of conn
type PL_AdminClient struct {
	client     trillian.TrillianAdminClient
	config     *AdminClientConfig
	configPath string
	conn       *grpc.ClientConn
}

// get a new admin client
func PL_GetAdminClient(configPath string) (*PL_AdminClient, error) {
	// read the config file
	config := &AdminClientConfig{}
	err := ReadAdminClientConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | ReadAdminClientConfigFromFile | %s", err.Error())
	}

	// get conn
	conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.LogAddress)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | Dial | %s", err.Error())
	}

	adminClient := trillian.NewTrillianAdminClient(conn)

	client := &PL_AdminClient{
		client:     adminClient,
		config:     config,
		configPath: configPath,
		conn:       conn,
	}

	return client, nil
}

// delete tree by treeID
func (client PL_AdminClient) DeleteTree(treeId int64) (bool, error) {
	req := &trillian.DeleteTreeRequest{TreeId: treeId}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(client.config.RpcMaxWaitingTimeInSec))
	defer cancel()

	resp, err := client.client.DeleteTree(ctx, req)
	if err != nil {
		return false, fmt.Errorf("DeleteTree | DeleteTree | %s", err.Error())
	}

	return resp.Deleted, nil
}

// create a new tree (Merkle Tree)
func (client PL_AdminClient) CreateNewTree() (*trillian.Tree, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(client.config.RpcMaxWaitingTimeInSec))
	defer cancel()

	req := client.generateCreateTreeReq()

	// new log client, used to init the tree
	logClient := trillian.NewTrillianLogClient(client.conn)

	// init the tree
	tree, err := trillianClient.CreateAndInitTree(ctx, req, client.client, logClient)
	if err != nil {
		return nil, fmt.Errorf("CreateNewTree | CreateAndInitTree | %s", err.Error())
	}

	// write tree info to files.
	err = client.writeTreeToFile(tree)
	return tree, nil
}

func (client PL_AdminClient) generateCreateTreeReq() *trillian.CreateTreeRequest {
	createRequest := &trillian.CreateTreeRequest{Tree: &trillian.Tree{
		TreeState:       trillian.TreeState_ACTIVE,
		TreeType:        trillian.TreeType_LOG,
		DisplayName:     client.config.DisplayName,
		Description:     client.config.Description,
		MaxRootDuration: durationpb.New(time.Second * time.Duration(client.config.RpcMaxWaitingTimeInSec)),
	}}

	return createRequest
}

func (client PL_AdminClient) writeTreeToFile(tree *trillian.Tree) error {
	file, err := json.MarshalIndent(tree, "", " ")
	if err != nil {
		return fmt.Errorf("writeTreeToFile | MarshalIndent | %s", err.Error())
	}

	err = ioutil.WriteFile(client.config.OutPutPath+"/treesConfig/"+strconv.FormatInt(tree.TreeId, 10), file, 0644)
	if err != nil {
		return fmt.Errorf("writeTreeToFile | WriteFile | %s", err.Error())
	}
	return nil
}
