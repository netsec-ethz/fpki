package logClient

import (
	"context"
	"fmt"
	"sync"

	common "common.FPKI.github.com"
	base64 "encoding/base64"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"time"
)

// what will a LogCLient do?
// 1. Add leaves to the log
// 2. Get the inclusion proof for one leaf
// 3. Get the tree head
// No verification will be done here;

// PL_LogClient represents a client for a given Trillian log instance.
type PL_LogClient struct {
	client          trillian.TrillianLogClient
	hasher          merkle.LogHasher
	config          *PL_LogClientConfig
	treeId          int64
	currentTreeSize int64

	// current log root
	logRoot     *types.LogRootV1
	logRootLock sync.Mutex
}

type PoIAndSTH struct {
	PoIs []*trillian.Proof
	STH  types.LogRootV1
}

// NewFromTree creates a new LogClient given a tree ID.
func PL_NewLogClient(configPath string, treeId int64) (*PL_LogClient, error) {
	config := &PL_LogClientConfig{}
	err := ReadLogClientConfigFromFile(config, configPath)
	if err != nil {
		return nil, err
	}

	conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.RPCAddress)
	logClient := trillian.NewTrillianLogClient(conn)

	return &PL_LogClient{
		client: logClient,
		hasher: rfc6962.DefaultHasher,
		config: config,
		treeId: treeId,
	}, nil
}

func (c *PL_LogClient) SetTreeId(treeID int64) {
	c.treeId = treeID
}

// fetch inclusion proof for one leaf
// TODO: what if the tree size is smaller than the current max tree size?
func (c *PL_LogClient) FetchInclusion(ctx context.Context, data []byte, treeSize int64) (*PoIAndSTH, error) {
	// build leaf
	leaf := c.BuildLeaf(data)

	request := &trillian.GetInclusionProofByHashRequest{
		LogId:    c.treeId,
		LeafHash: leaf.MerkleLeafHash,
		TreeSize: treeSize,
	}

	result := &PoIAndSTH{}

	for {
		resp, err := c.client.GetInclusionProofByHash(ctx, request)
		if err != nil && status.Code(err) == codes.NotFound {
			time.Sleep(10 * time.Millisecond)
			continue
		} else if len(resp.Proof) > 0 {
			result.PoIs = resp.Proof
			if err := result.STH.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
				return nil, fmt.Errorf("FetchInclusion | UnmarshalBinary: %v", err)
			}
			break
		} else if err != nil {
			return nil, fmt.Errorf("FetchInclusion | GetInclusionProofByHash: %v", err)
		}
	}

	return result, nil
}

// get current log root of the target tree
func (c *PL_LogClient) GetCurrentLogRoot(ctx context.Context) (*types.LogRootV1, error) {
	req := &trillian.GetLatestSignedLogRootRequest{
		LogId:         c.treeId,
		FirstTreeSize: c.currentTreeSize,
	}
	logRootResp, err := c.client.GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | GetLatestSignedLogRoot: %v", err)
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRootResp.SignedLogRoot.LogRoot); err != nil {
		return nil, fmt.Errorf("GetCurrentLogRoot | UnmarshalBinary: %v", err)
	}
	return &root, nil
}

// TODO: Mutex
func (c *PL_LogClient) UpdateLogRoot(ctx context.Context) error {
	root, err := c.GetCurrentLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateLogRoot | GetCurrentLogRoot: %v", err)
	}

	c.logRoot = root
	return nil
}

func (c *PL_LogClient) UpdateTreeSize(ctx context.Context) error {
	err := c.UpdateLogRoot(ctx)
	if err != nil {
		return fmt.Errorf("UpdateTreeSize | UpdateLogRoot: %v", err)
	}

	c.currentTreeSize = int64(c.logRoot.TreeSize)
	return nil
}

// BuildLeaf runs the leaf hasher over data and builds a leaf.
func (c *PL_LogClient) BuildLeaf(data []byte) *trillian.LogLeaf {
	leafHash := c.hasher.HashLeaf(data)
	return &trillian.LogLeaf{
		LeafValue:      data,
		MerkleLeafHash: leafHash,
	}
}

func (c *PL_LogClient) GetConsistencyProof(ctx context.Context, trusted *types.LogRootV1, newRoot *types.LogRootV1) ([][]byte, error) {
	req := &trillian.GetConsistencyProofRequest{
		LogId:          c.treeId,
		FirstTreeSize:  int64(trusted.TreeSize),
		SecondTreeSize: int64(newRoot.TreeSize),
	}

	resp, err := c.client.GetConsistencyProof(ctx, req)

	return resp.Proof.Hashes, err
}

// QueueLeaf adds a leaf to a Trillian log without blocking.
// AlreadyExists is considered a success case by this function.
func (c *PL_LogClient) QueueLeaf(ctx context.Context, data []byte) error {
	leaf := c.BuildLeaf(data)
	_, err := c.client.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: c.treeId,
		Leaf:  leaf,
	})
	return err
}

// Queue a list of leaves
func (c *PL_LogClient) QueueLeaves(ctx context.Context, data [][]byte) error {
	for _, leaf := range data {
		err := c.QueueLeaf(ctx, leaf)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO: What if the same leaves are added to log?
func (c *PL_LogClient) AddLeaves(ctx context.Context, data [][]byte, withProof bool) (map[string]*PoIAndSTH, error) {
	// measure the time
	start := time.Now()
	if err := c.QueueLeaves(ctx, data); err != nil {
		return nil, fmt.Errorf("QueueLeaf(): %v", err)
	}
	elapsed := time.Since(start)
	fmt.Println("queue leaves succeed!")
	fmt.Println(elapsed)

	time.Sleep(2000 * time.Millisecond)

	if withProof {
		start = time.Now()
		c.UpdateTreeSize(ctx)

		var proofs = make(map[string]*PoIAndSTH)

		for _, leafBytes := range data {
			proof, err := c.FetchInclusion(ctx, leafBytes, c.currentTreeSize)
			if err != nil {
				return nil, fmt.Errorf("WaitForInclusion(): %v", err)
			}

			// hash to get the SPT fileName
			rpcHash := c.hasher.HashLeaf(leafBytes)
			fileName := base64.URLEncoding.EncodeToString(rpcHash)

			proofs[fileName] = proof
		}

		elapsed = time.Since(start)
		fmt.Println("get proof succeed!")
		fmt.Println(elapsed)

		return proofs, nil
	}
	return nil, nil
}

func (c *PL_LogClient) QueueRPCs(ctx context.Context, fileNames []string) error {
	data := [][]byte{}
	// read SPT from "fileTranfer" folder
	for _, filaName := range fileNames {
		filaPath := c.config.RPCPath + "/" + filaName

		rpc := &common.RPC{}
		// read RPC from file
		err := common.Json_FileToRPC(rpc, filaPath)
		if err != nil {
			return fmt.Errorf("QueueRPCs(): %v", err)
		}

		// serialise rpc
		bytes, err := common.Json_StrucToBytes(rpc)
		if err != nil {
			return fmt.Errorf("QueueRPCs | Json_StrucToBytes: %v", err)
		}

		data = append(data, bytes)
	}

	// get inclusion proofs
	proofMap, err := c.AddLeaves(ctx, data, true)
	if err != nil {
		return fmt.Errorf("QueueRPCs | AddLeaves: %v", err)
	}

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

		sptBytes, err := common.Json_StrucToBytes(spt)
		if err != nil {
			return fmt.Errorf("QueueRPCs | Json_StrucToBytes: %v", err)
		}

		err = ioutil.WriteFile(c.config.OutPutPath+"/spt/"+k, sptBytes, 0644)
		if err != nil {
			return fmt.Errorf("QueueRPCs | WriteFile: %v", err)
		}
	}

	err = common.Json_StrucToFile(c.logRoot, c.config.OutPutPath+"/logRoot/logRoot")
	return nil
}

// ------------------------------------------------------------------------------------------
//                                 Deprecated funcs
// ------------------------------------------------------------------------------------------

/*

func (c *PL_LogClient) AddLeaf_Batch(data []byte) {
	c.batchLock.Lock()
	defer c.batchLock.Unlock()

	c.leafBatch = append(c.leafBatch, data)
}

func (c *PL_LogClient) QueueLeaf_Batch(ctx context.Context) error {
	c.batchLock.Lock()
	defer c.batchLock.Unlock()
	// calculate the size of current batch
	batchSize := len(c.leafBatch)

	leaves := make([]*trillian.LogLeaf, 0, batchSize)

	for i, leafBytes := range c.leafBatch {
		leaf := c.BuildLeaf(leafBytes)
		leaf.LeafIndex = int64(i)
		leaves = append(leaves, leaf)
	}

	_, err := c.client.AddSequencedLeaves(ctx, &trillian.AddSequencedLeavesRequest{
		LogId:  c.treeId,
		Leaves: leaves,
	})
	return err
}
*/
