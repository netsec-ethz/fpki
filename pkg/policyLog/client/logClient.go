package logClient

import (
	common "common.FPKI.github.com"
	"context"
	"fmt"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/rfc6962"
	"sync"
	"time"
)

// what will a LogCLient do?
// 1. Add leaves to the log
// 2. Get the inclusion proof for one leaf
// 3. Get the tree head
// 4. Get consistency proof between two tree head
// No verification will be done here;

// PL_LogClient represents a client for a given Trillian log instance.
type PL_LogClient struct {
	worker []trillian.TrillianLogClient
	config *PL_LogClientConfig

	// target tree ID
	// for log client, normally there will only be one tree
	treeId int64

	// size of the tree
	currentTreeSize int64

	// current log root
	logRoot     *types.LogRootV1
	logRootLock sync.Mutex
}

type PoIAndSTH struct {
	PoIs []*trillian.Proof
	STH  types.LogRootV1
}

// result returned by worker
type FetchInclusionResult struct {
	leafName string
	PoI      *PoIAndSTH
	err      error
}

// NewFromTree creates a new LogClient given a tree ID.
func PL_NewLogClient(configPath string, treeId int64) (*PL_LogClient, error) {
	// read config from file
	config := &PL_LogClientConfig{}
	err := ReadLogClientConfigFromFile(config, configPath)
	if err != nil {
		return nil, err
	}

	// init worker pool
	workers := []trillian.TrillianLogClient{}
	for i := 1; i <= config.NumOfWorker; i++ {
		conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.RPCAddress)
		if err != nil {
			return nil, fmt.Errorf("PL_NewLogClient | GetGRPCConn: %v", err)
		}
		logClient := trillian.NewTrillianLogClient(conn)
		workers = append(workers, logClient)
	}

	return &PL_LogClient{
		worker: workers,
		config: config,
		treeId: treeId,
	}, nil
}

func (c *PL_LogClient) SetTreeId(treeID int64) {
	c.treeId = treeID
}

// get current log root of the target tree
func (c *PL_LogClient) GetCurrentLogRoot(ctx context.Context) (*types.LogRootV1, error) {
	req := &trillian.GetLatestSignedLogRootRequest{
		LogId:         c.treeId,
		FirstTreeSize: c.currentTreeSize,
	}

	// use one worker for this
	logRootResp, err := c.worker[0].GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | GetLatestSignedLogRoot: %v", err)
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRootResp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | UnmarshalBinary: %v", err)
	}
	return &root, nil
}

// update the current log root
func (c *PL_LogClient) UpdateLogRoot(ctx context.Context) error {
	root, err := c.GetCurrentLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateLogRoot | GetCurrentLogRoot: %v", err)
	}
	c.logRootLock.Lock()
	defer c.logRootLock.Unlock()
	c.logRoot = root
	return nil
}

// update the tree size
func (c *PL_LogClient) UpdateTreeSize(ctx context.Context) error {
	err := c.UpdateLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateTreeSize | UpdateLogRoot: %v", err)
	}

	c.currentTreeSize = int64(c.logRoot.TreeSize)
	return nil
}

// get consistency proof between two log root
func (c *PL_LogClient) GetConsistencyProof(ctx context.Context, trusted *types.LogRootV1, newRoot *types.LogRootV1) ([][]byte, error) {
	req := &trillian.GetConsistencyProofRequest{
		LogId:          c.treeId,
		FirstTreeSize:  int64(trusted.TreeSize),
		SecondTreeSize: int64(newRoot.TreeSize),
	}

	resp, err := c.worker[0].GetConsistencyProof(ctx, req)

	return resp.Proof.Hashes, err
}

// read RPC -> queue RPC -> fetch PoI and STH -> write SPT
func (c *PL_LogClient) QueueRPCs(ctx context.Context, fileNames []string) error {
	// read RPC from files
	data, err := c.readRPCFromFileToBytes(fileNames)
	start := time.Now()

	// add ;eaves
	err = c.AddLeaves(ctx, data)
	if err != nil {
		return fmt.Errorf("QueueRPCs | addLeaves: %v", err)
	}

	// calculate time
	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	// record previous tree size
	prevTreeSize := c.currentTreeSize

	// wait for the leaves to be added to the log
	for {
		err = c.UpdateTreeSize(ctx)
		if err != nil {
			return fmt.Errorf("QueueRPCs | UpdateTreeSize: %v", err)
		}

		if c.currentTreeSize == prevTreeSize+int64(len(fileNames)) {
			break
		}

		// wait 50 ms before next query
		time.Sleep(50 * time.Millisecond)
	}

	start = time.Now()

	// fetch the inclusion
	proofMap, err := c.FetchInclusions(ctx, data)
	if err != nil {
		return fmt.Errorf("QueueRPCs | FetchInclusions: %v", err)
	}

	elapsed = time.Since(start)
	fmt.Println("fetch proofs succeed!")
	fmt.Println(elapsed)

	// store proof to SPT file
	err = c.storeProofMapToSPT(proofMap)
	if err != nil {
		return fmt.Errorf("QueueRPCs | storeProofMapToSPT: %v", err)
	}

	// store the STH as well; not necessary
	err = common.Json_StrucToFile(c.logRoot, c.config.OutPutPath+"/logRoot/logRoot")
	return nil
}

// file -> RPC -> bytes
func (c *PL_LogClient) readRPCFromFileToBytes(fileNames []string) ([][]byte, error) {
	data := [][]byte{}
	// read SPT from "fileTranfer" folder
	for _, filaName := range fileNames {
		filaPath := c.config.RPCPath + "/" + filaName

		rpc := &common.RPC{}
		// read RPC from file
		err := common.Json_FileToRPC(rpc, filaPath)
		if err != nil {
			return nil, fmt.Errorf("QueueRPCs(): %v", err)
		}

		// serialise rpc
		bytes, err := common.Json_StrucToBytes(rpc)
		if err != nil {
			return nil, fmt.Errorf("QueueRPCs | Json_StrucToBytes: %v", err)
		}

		data = append(data, bytes)
	}
	return data, nil
}

func (c *PL_LogClient) storeProofMapToSPT(proofMap map[string]*PoIAndSTH) error {
	// for every proof in the map
	for k, v := range proofMap {
		proofBytes := [][]byte{}

		// serialise proof to bytes
		for _, proof := range v.PoIs {
			bytes, err := common.Json_StrucToBytes(proof)
			if err != nil {
				return fmt.Errorf("QueueRPCs | Json_StrucToBytes: %v", err)
			}
			proofBytes = append(proofBytes, bytes)
		}

		// serialise log root (signed tree head) to bytes
		sth, err := common.Json_StrucToBytes(&v.STH)
		if err != nil {
			return fmt.Errorf("QueueRPCs | Json_StrucToBytes: %v", err)
		}

		// attach PoI and STH to SPT
		// TODO: fill in the other fields
		spt := &common.SPT{
			PoI: proofBytes,
			STH: sth,
		}

		// store SPT to file
		err = common.Json_StrucToFile(spt, c.config.OutPutPath+"/spt/"+k)
		if err != nil {
			return fmt.Errorf("QueueRPCs | Json_StrucToFile: %v", err)
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