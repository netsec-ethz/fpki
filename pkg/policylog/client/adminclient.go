package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/google/trillian"
	trillianClient "github.com/google/trillian/client"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

// admin client is mainly used for managing trees;
// For example, create tree, list trees or delete tree

// TODO: termination of conn
type PLAdminClient struct {
	client     trillian.TrillianAdminClient
	config     *AdminClientConfig
	configPath string
	conn       *grpc.ClientConn
}

// get a new admin client
func PLGetAdminClient(configPath string) (*PLAdminClient, error) {
	// read the config file
	config := &AdminClientConfig{}
	err := ReadAdminClientConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | ReadAdminClientConfigFromFile | %s", err.Error())
	}

	// get conn
	conn, err := getGRPCConn(config.MaxReceiveMessageSize, config.LogAddress)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | Dial | %s", err.Error())
	}

	adminClient := trillian.NewTrillianAdminClient(conn)

	client := &PLAdminClient{
		client:     adminClient,
		config:     config,
		configPath: configPath,
		conn:       conn,
	}

	return client, nil
}

// create a new tree (Merkle Tree)
func (client PLAdminClient) CreateNewTree() (*trillian.Tree, error) {
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
	return tree, err
}

func (client PLAdminClient) generateCreateTreeReq() *trillian.CreateTreeRequest {
	createRequest := &trillian.CreateTreeRequest{Tree: &trillian.Tree{
		TreeState:       trillian.TreeState_ACTIVE,
		TreeType:        trillian.TreeType_LOG,
		DisplayName:     client.config.DisplayName,
		Description:     client.config.Description,
		MaxRootDuration: durationpb.New(time.Second * time.Duration(client.config.RpcMaxWaitingTimeInSec)),
	}}

	return createRequest
}

func (client PLAdminClient) writeTreeToFile(tree *trillian.Tree) error {
	file, err := json.MarshalIndent(tree, "", " ")
	if err != nil {
		return fmt.Errorf("writeTreeToFile | MarshalIndent | %s", err.Error())
	}

	err = ioutil.WriteFile(client.config.OutPutPath+"/trees_config/"+strconv.FormatInt(tree.TreeId, 10), file, 0644)
	if err != nil {
		return fmt.Errorf("writeTreeToFile | WriteFile | %s", err.Error())
	}
	return nil
}
