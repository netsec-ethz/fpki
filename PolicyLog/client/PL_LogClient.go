package PL_LogClient

import (
	"context"
	"fmt"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	//leafBatch       [][]byte
	//batchLock       sync.Mutex
}

// New returns a new PL_LogClient.
func New(config *PL_LogClientConfig, client trillian.TrillianLogClient, treeId int64) *PL_LogClient {
	return &PL_LogClient{
		client: client,
		hasher: rfc6962.DefaultHasher,
		config: config,
		treeId: treeId,
	}
}

// NewFromTree creates a new LogClient given a tree config.
func PL_NewLogClient(configPath string, treeId int64) (*PL_LogClient, error) {
	config := &PL_LogClientConfig{}
	err := Json_ReadLogConfigFromFile(config, configPath)
	if err != nil {
		return nil, err
	}

	conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.RPCAddress)
	logClient := trillian.NewTrillianLogClient(conn)

	return New(config, logClient, treeId), nil
}

func (c *PL_LogClient) SetTreeId(treeID int64) {
	c.treeId = treeID
}

func (c *PL_LogClient) FetchInclusion(ctx context.Context, data []byte, treeSize int64) ([]*trillian.Proof, error) {
	leaf := c.BuildLeaf(data)

	request := &trillian.GetInclusionProofByHashRequest{
		LogId:    c.treeId,
		LeafHash: leaf.MerkleLeafHash,
		TreeSize: treeSize,
	}

	var proof []*trillian.Proof
	for {
		resp, err := c.client.GetInclusionProofByHash(ctx, request)
		if err != nil && status.Code(err) == codes.NotFound {
			time.Sleep(200 * time.Millisecond)
			continue
		} else if len(resp.Proof) > 0 {
			proof = resp.Proof
			break
		}
	}

	return proof, nil
}

func (c *PL_LogClient) GetCurrentLogRoot(ctx context.Context) (*types.LogRootV1, error) {
	req := &trillian.GetLatestSignedLogRootRequest{
		LogId:         c.treeId,
		FirstTreeSize: c.currentTreeSize,
	}
	logRootResp, err := c.client.GetLatestSignedLogRoot(ctx, req)
	if err != nil {
		return nil, err
	}

	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRootResp.SignedLogRoot.LogRoot); err != nil {
		return nil, err
	}

	return &root, nil
}

func (c *PL_LogClient) UpdateTreeSize(ctx context.Context) error {
	logRoot, err := c.GetCurrentLogRoot(ctx)
	if err != nil {
		return err
	}

	fmt.Println(logRoot.TreeSize)

	c.currentTreeSize = int64(logRoot.TreeSize)
	return nil
}

// BuildLeaf runs the leaf hasher over data and builds a leaf.
// TODO(pavelkalinnikov): This can be misleading as it creates a partially
// filled LogLeaf. Consider returning a pair instead, or leafHash only.
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

// AddLeaf adds leaf to the append only log.
// Blocks and continuously updates the trusted root until a successful inclusion proof
// can be retrieved.
func (c *PL_LogClient) AddLeaf(ctx context.Context, data []byte, treeSize int64, withProof bool) ([]*trillian.Proof, error) {
	if err := c.QueueLeaf(ctx, data); err != nil {
		return nil, fmt.Errorf("QueueLeaf(): %v", err)
	}

	if withProof {
		proof, err := c.FetchInclusion(ctx, data, treeSize)
		if err != nil {
			return nil, fmt.Errorf("WaitForInclusion(): %v", err)
		}
		return proof, nil
	}
	return nil, nil
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
func (c *PL_LogClient) AddLeaves(ctx context.Context, data [][]byte, withProof bool) (map[string][]*trillian.Proof, error) {
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

		var proofs = map[string][]*trillian.Proof{}

		for _, leafBytes := range data {
			proof, err := c.FetchInclusion(ctx, leafBytes, c.currentTreeSize)
			if err != nil {
				return nil, fmt.Errorf("WaitForInclusion(): %v", err)
			}

			proofs[string(leafBytes)] = proof

		}

		elapsed = time.Since(start)
		fmt.Println("get proof succeed!")
		fmt.Println(elapsed)

		return proofs, nil

	}
	return nil, nil
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
