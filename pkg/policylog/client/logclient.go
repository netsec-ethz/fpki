package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	common "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/transparency-dev/merkle/rfc6962"
)

// TODO(Yongzhe, CRITICAL): Around line 183, the func will wait forever, if one identical leaf is added to the trillian
// Possible cause: Trillian will update the identical leaf, rather than add a new one... So the tree size will not grow
// To Be Solved Later...

// what will a LogCLient do?
// 1. Add leaves to the log
// 2. Get the inclusion proof for one leaf
// 3. Get the tree head
// 4. Get consistency proof between two tree head
// No verification will be done here;

// LogClient represents a client for a given Trillian log instance.
type LogClient struct {
	worker []trillian.TrillianLogClient
	config *LogClientConfig

	// target tree ID
	// for log client, normally there will only be one tree
	treeId int64

	// size of the tree
	currentTreeSize int64

	// current log root
	logRoot     *types.LogRootV1
	logRootLock sync.Mutex
}

// QueueRPCResult: result of queue a batch of RPC
type QueueRPCResult struct {
	// how many leaves are appended successfully
	NumOfSucceedAddedLeaves int
	// the bytes of leaves which are not added
	FailToAddLeaves [][]byte
	// error list
	AddLeavesErrs []error
	// how many proofs are appended successfully
	NumOfRetrivedLeaves int
	// the bytes of leaves which are not retrived
	FailToRetriveLeaves [][]byte
	// name of the failed leaf; name is an identical name for every rpc; name = base64URLencode(hash(rpc))
	FailToRetriveLeavesName []string
	// error list
	RetriveLeavesErrs []error
}

// NewLogClient: creates a new LogClient given a tree ID.
func NewLogClient(configPath string, treeId int64) (*LogClient, error) {
	// read config from file
	config := &LogClientConfig{}
	err := ReadLogClientConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("NewLogClient | ReadLogClientConfigFromFile | %w", err)
	}

	// init worker pool
	workers := []trillian.TrillianLogClient{}
	for i := 1; i <= config.NumOfWorker; i++ {
		conn, err := getGRPCConn(config.MaxReceiveMessageSize, config.RPCAddress)
		if err != nil {
			return nil, fmt.Errorf("NewLogClient | GetGRPCConn: %w", err)
		}
		logClient := trillian.NewTrillianLogClient(conn)
		workers = append(workers, logClient)
	}

	return &LogClient{
		worker: workers,
		config: config,
		treeId: treeId,
	}, nil
}

// SetTreeId: Set the target tree ID
func (c *LogClient) SetTreeId(treeID int64) {
	c.treeId = treeID
}

// GetCurrentLogRoot:  get current log root of the target tree
func (c *LogClient) GetCurrentLogRoot(ctx context.Context) (*types.LogRootV1, error) {
	req := &trillian.GetLatestSignedLogRootRequest{
		LogId:         c.treeId,
		FirstTreeSize: c.currentTreeSize,
	}

	// use one worker for this
	logRootResp, err := c.worker[0].GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | GetLatestSignedLogRoot: %w", err)
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRootResp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | UnmarshalBinary: %w", err)
	}
	return &root, nil
}

// UpdateTreeSize: update the tree size
func (c *LogClient) UpdateTreeSize(ctx context.Context) error {
	err := c.updateLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateTreeSize | UpdateLogRoot: %w", err)
	}

	c.currentTreeSize = int64(c.logRoot.TreeSize)
	return nil
}

// GetConsistencyProof: get consistency proof between two log root
func (c *LogClient) GetConsistencyProof(ctx context.Context, trusted *types.LogRootV1, newRoot *types.LogRootV1) ([][]byte, error) {
	req := &trillian.GetConsistencyProofRequest{
		LogId:          c.treeId,
		FirstTreeSize:  int64(trusted.TreeSize),
		SecondTreeSize: int64(newRoot.TreeSize),
	}

	// use one single thread to do this.
	resp, err := c.worker[0].GetConsistencyProof(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetConsistencyProof | %w", err)
	}

	return resp.Proof.Hashes, nil
}

// QueueRPCs: queue rpcs and generate spts
// steps:
// 1. read rpc from "fileExchange" folder; TODO: replace the folder by http later
// 2. add the rpc to the log
// 3. update the tree size
// 4. fetch proof for successfully added leaves
// 5. generate spts using proofs, and write them to the "fileExchange" folder
func (c *LogClient) QueueRPCs(ctx context.Context, fileNames []string) (*QueueRPCResult, error) {
	queueRPCResult := &QueueRPCResult{}

	// one file will only contain one RPC
	leafNum := len(fileNames)

	// read RPC from files
	data, err := c.readRPCFromFileToBytes(fileNames)
	if err != nil {
		return nil, fmt.Errorf("QueueRPCs | readRPCFromFileToBytes: %w", err)
	}

	start := time.Now()

	// add leaves
	addLeavesErrors := c.AddLeaves(ctx, data)

	// process the errors from AddLeaves()
	queueRPCResult.NumOfSucceedAddedLeaves = leafNum - len(addLeavesErrors.Errs)
	queueRPCResult.FailToAddLeaves = addLeavesErrors.FailedLeaves

	// calculate time
	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	// record previous tree size
	prevTreeSize := c.currentTreeSize

	// wait for the leaves to be added to the log (BUG FOUND!!!!!!)
	for {
		err = c.UpdateTreeSize(ctx)
		if err != nil {
			return queueRPCResult, fmt.Errorf("QueueRPCs | UpdateTreeSize: %w", err)
		}
		if c.currentTreeSize == prevTreeSize+int64(queueRPCResult.NumOfSucceedAddedLeaves) {
			break
		}
		// wait 50 ms before next query
		time.Sleep(50 * time.Millisecond)
	}

	start = time.Now()

	// fetch the inclusion
	fetchInclusionResult := c.FetchInclusions(ctx, data)

	// precess fetch inclusion errors
	queueRPCResult.NumOfRetrivedLeaves = len(fetchInclusionResult.PoIs)
	queueRPCResult.FailToRetriveLeaves = fetchInclusionResult.FailedLeaves
	queueRPCResult.FailToRetriveLeavesName = fetchInclusionResult.FailedLeavesName
	queueRPCResult.RetriveLeavesErrs = fetchInclusionResult.Errs

	elapsed = time.Since(start)
	fmt.Println("fetch proofs succeed!")
	fmt.Println(elapsed)

	// queueRPCResult will always be returned, even if error occurs in the future

	// store proof to SPT file
	err = c.storeProofMapToSPT(fetchInclusionResult.PoIs)
	if err != nil {
		return queueRPCResult, fmt.Errorf("QueueRPCs | storeProofMapToSPT: %w", err)
	}

	// store the STH as well; not necessary
	err = common.JsonStrucToFile(c.logRoot, c.config.OutPutPath+"/logRoot/logRoot")
	if err != nil {
		return queueRPCResult, fmt.Errorf("QueueRPCs | JsonStrucToFile: %w", err)
	}

	return queueRPCResult, nil
}

// file -> RPC -> bytes
func (c *LogClient) readRPCFromFileToBytes(fileNames []string) ([][]byte, error) {
	data := [][]byte{}
	// read SPT from "fileTranfer" folder
	for _, filaName := range fileNames {
		filaPath := c.config.RPCPath + "/" + filaName

		rpc := &common.RPC{}
		// read RPC from file
		err := common.JsonFileToRPC(rpc, filaPath)
		if err != nil {
			return nil, fmt.Errorf("readRPCFromFileToBytes | JsonFileToRPC %w", err)
		}

		// serialise rpc
		bytes, err := common.JsonStrucToBytes(rpc)
		if err != nil {
			return nil, fmt.Errorf("readRPCFromFileToBytes | JsonStrucToBytes: %w", err)
		}

		data = append(data, bytes)
	}
	return data, nil
}

// read elements in the proof map, and turn it into a SPT, then store them
func (c *LogClient) storeProofMapToSPT(proofMap map[string]*PoIAndSTH) error {
	// for every proof in the map
	for k, v := range proofMap {
		proofBytes := [][]byte{}

		// serialise proof to bytes
		for _, proof := range v.PoIs {
			bytes, err := common.JsonStrucToBytes(proof)
			if err != nil {
				return fmt.Errorf("storeProofMapToSPT | JsonStrucToBytes: %w", err)
			}
			proofBytes = append(proofBytes, bytes)
		}

		// serialise log root (signed tree head) to bytes
		sth, err := common.JsonStrucToBytes(&v.STH)
		if err != nil {
			return fmt.Errorf("storeProofMapToSPT | JsonStrucToBytes: %w", err)
		}

		// attach PoI and STH to SPT
		// TODO: fill in the other fields
		spt := &common.SPT{
			PoI: proofBytes,
			STH: sth,
		}

		// store SPT to file
		err = common.JsonStrucToFile(spt, c.config.OutPutPath+"/spt/"+k)
		if err != nil {
			return fmt.Errorf("storeProofMapToSPT | JsonStrucToFile: %w", err)
		}
	}
	return nil
}

// BuildLeaf runs the leaf hasher over data and builds a leaf.
func buildLeaf(data []byte) *trillian.LogLeaf {
	leafHash := rfc6962.DefaultHasher.HashLeaf(data)
	return &trillian.LogLeaf{
		LeafValue:      data,
		MerkleLeafHash: leafHash,
	}
}

// update the current log root
func (c *LogClient) updateLogRoot(ctx context.Context) error {
	root, err := c.GetCurrentLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateLogRoot | GetCurrentLogRoot: %w", err)
	}
	c.logRootLock.Lock()
	defer c.logRootLock.Unlock()
	c.logRoot = root
	return nil
}
