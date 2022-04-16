package PL_LogClient

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

type PL_AdminClient struct {
	client     trillian.TrillianAdminClient
	config     *PL_AdminClientConfig
	configPath string
	conn       *grpc.ClientConn
}

func PL_GetAdminClient(configPath string) (*PL_AdminClient, error) {
	config := &PL_AdminClientConfig{}
	err := Json_ReadConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | Json_ReadConfigFromFile | %s", err.Error())
	}

	// get conn
	conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.LogAddress)
	if err != nil {
		return nil, fmt.Errorf("PL_GetAdminClient | Dial | %s", err.Error())
	}

	//defer conn.Close()
	adminClient := trillian.NewTrillianAdminClient(conn)

	client := PL_AdminClient{
		client:     adminClient,
		config:     config,
		configPath: configPath,
		conn:       conn,
	}

	return &client, nil
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

func (client PL_AdminClient) CreateNewTree() (*trillian.Tree, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(client.config.RpcMaxWaitingTimeInSec))
	defer cancel()

	req := client.generateCreateTreeReq()

	logClient := trillian.NewTrillianLogClient(client.conn)

	tree, err := trillianClient.CreateAndInitTree(ctx, req, client.client, logClient)
	if err != nil {
		return nil, fmt.Errorf("CreateNewTree | CreateAndInitTree | %s", err.Error())
	}

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
		return err
	}

	err = ioutil.WriteFile(client.config.OutPutPath+"/"+strconv.FormatInt(tree.TreeId, 10), file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (client PL_AdminClient) loadTreeFromFile(treeID int64) (*trillian.Tree, error) {
	tree := &trillian.Tree{}
	treeFilePath := client.config.OutPutPath + "/" + strconv.FormatInt(treeID, 10)

	file, err := ioutil.ReadFile(treeFilePath)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(file), tree)
	if err != nil {
		return nil, err
	}

	return tree, nil
}
