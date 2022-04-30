package client

import (
	"context"
	base64 "encoding/base64"
	"time"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// this file contains multi-thread versions of the "Add_leaf" and "Retrive_Proof"
// the speed is 4-5 times faster than the single thread version (if number of worker > 5)

// general idea:
// leader distributes the work, collects response from worker, and precess the result.
// worker do the work, and returns the result to the leader.
// When all the work is finished, leader will return the result

// IMPORTANT!!!!! AddLeaves() is not idempotent! Run func for same leaf will add the leaf multiple times.
//                FetchInclusions() is not deterministic. If the tree size is changed (new leaves are added), STH and PoI will also change.

// result from worker; only for internal use
type addLeavesResultFromWorker struct {
	leafData []byte
	err      error
}

// result returned by AddLeaf
type addLeavesResult struct {
	FailedLeaves [][]byte
	Errs         []error
}

// result from worker; only for internal use
type fetchInclusionResultFromWorker struct {
	leafName       string
	PoI            *PoIAndSTH
	failedLeafData []byte
	err            error
}

// result returned by FetchInclusions()
type fetchInclusionResult struct {
	PoIs             map[string]*PoIAndSTH
	FailedLeaves     [][]byte
	FailedLeavesName []string
	Errs             []error
}

// PoIAndSTH: contains Sign Tree Head and Proof of Inclusion for one leaf
type PoIAndSTH struct {
	PoIs []*trillian.Proof
	STH  types.LogRootV1
}

// func for single worker to add a leaf
func worker_addLeaf(ctx context.Context, worker trillian.TrillianLogClient, workChan <-chan string, resultChan chan<- addLeavesResultFromWorker, treeId int64) {
	for {
		// read leaf data from channel
		leafData, ok := <-workChan

		// if channel is closed -> return
		if !ok {
			return
		}

		// build the log leaf
		leaf := buildLeaf([]byte(leafData))

		// add the leaf to the server
		// response is not important, so ignore it
		_, err := worker.QueueLeaf(ctx, &trillian.QueueLeafRequest{
			LogId: treeId,
			Leaf:  leaf,
		})

		// copy the failed leaf and err
		result := addLeavesResultFromWorker{}
		if err != nil {
			result.leafData = []byte(leafData)
			result.err = err
		}

		// return the result (err)
		resultChan <- result
	}
}

// AddLeaves: Queue a list of leaves
func (c *PLLogClient) AddLeaves(ctx context.Context, data [][]byte) *addLeavesResult {
	// init result
	result := &addLeavesResult{
		Errs:         []error{},
		FailedLeaves: [][]byte{[]byte{}},
	}

	// channels to workers
	workChan := make(chan string)

	// channels from worker, contains results
	resultChan := make(chan addLeavesResultFromWorker)

	// spawn child threads
	for i := 0; i < len(c.worker); i++ {
		go worker_addLeaf(ctx, c.worker[i], workChan, resultChan, c.treeId)
	}

	// count how many jobs are distributed, and how many jobs are finished
	dataSize := len(data)
	jobCounter := 0
	resultCounter := 0

	// loop to send the work and receive the work
send_receive_loop:
	for {
		select {
		// when a worker accept a job
		case workChan <- string(data[jobCounter]):
			jobCounter = jobCounter + 1
			if jobCounter == dataSize {
				// if all the jobs are distributed, quit this loop and close the channel
				close(workChan)
				break send_receive_loop
			}

		// when a worker returns a result
		case workerResult := <-resultChan:
			if workerResult.err != nil {
				// if error is detected, records the error
				result.Errs = append(result.Errs, workerResult.err)
				result.FailedLeaves = append(result.FailedLeaves, workerResult.leafData)
			}

			resultCounter = resultCounter + 1
		}
	}

	// loop to receive the remaining results
	if resultCounter != dataSize {
		for {
			workerResult := <-resultChan
			if workerResult.err != nil {
				// if error is detected, records the error
				result.Errs = append(result.Errs, workerResult.err)
				result.FailedLeaves = append(result.FailedLeaves, workerResult.leafData)
			}

			resultCounter = resultCounter + 1
			if resultCounter == dataSize {
				close(resultChan)
				return result
			}
		}
	}
	// might not be reached
	return result
}

// func for a worker to fetch the inclusion
func worker_fetchInclusion(ctx context.Context, worker trillian.TrillianLogClient, workChan <-chan string, resultChan chan<- fetchInclusionResultFromWorker, treeId int64, treeSize int64) {
	for {
		// receive data from channel
		leafData, ok := <-workChan

		// if channel is closed -> return
		if !ok {
			return
		}

		// build leaf and init request
		leaf := buildLeaf([]byte(leafData))
		request := &trillian.GetInclusionProofByHashRequest{
			LogId:    treeId,
			LeafHash: leaf.MerkleLeafHash,
			TreeSize: treeSize,
		}

		// hash to get the SPT fileName(identical name for every rpc)
		rpcHash := rfc6962.DefaultHasher.HashLeaf([]byte(leafData))
		leafName := base64.URLEncoding.EncodeToString(rpcHash)

		workerResult := new(fetchInclusionResultFromWorker)

		workerResult.leafName = leafName

		// retry number counter
		tries := 0
	workerQueryLoop:
		for {
			// get result
			resp, err := worker.GetInclusionProofByHash(ctx, request)

			// if the leaf is not found -> try later
			if err != nil && status.Code(err) == codes.NotFound {
				// if retry for 10 times, return error
				if tries > 10 {
					workerResult.failedLeafData = []byte(leafData)
					workerResult.err = err
					resultChan <- *workerResult
					break workerQueryLoop
				}
				time.Sleep(10 * time.Millisecond)
				tries = tries + 1
				continue
			} else if err != nil {
				// send err back
				workerResult.failedLeafData = []byte(leafData)
				workerResult.err = err
				resultChan <- *workerResult
				break workerQueryLoop

				// normally, proof will > 0, except for when there is only one leaf in the log; ignore this situation
			} else if len(resp.Proof) > 0 {
				// init poiAndSTH
				poiAndSTH := new(PoIAndSTH)
				// when query succeeds
				poiAndSTH.PoIs = resp.Proof

				// marshall the log root (Signed Tree Head)
				if err := poiAndSTH.STH.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
					workerResult.err = err
					workerResult.failedLeafData = []byte(leafData)
					resultChan <- *workerResult
					break workerQueryLoop
				}

				workerResult.PoI = poiAndSTH
				workerResult.err = nil

				// send back
				resultChan <- *workerResult
				break workerQueryLoop
			}
		}
	}
}

// FetchInclusions: fetch inclusion proof for leaves
// similar to previous func
func (c *PLLogClient) FetchInclusions(ctx context.Context, leavesData [][]byte) *fetchInclusionResult {
	// init result
	fetchInclusionResult := new(fetchInclusionResult)
	fetchInclusionResult.PoIs = make(map[string]*PoIAndSTH)

	workChan := make(chan string)
	resultChan := make(chan fetchInclusionResultFromWorker)

	for i := 0; i < len(c.worker); i++ {
		go worker_fetchInclusion(ctx, c.worker[i], workChan, resultChan, c.treeId, c.currentTreeSize)
	}

	dataSize := len(leavesData)
	jobCounter := 0
	resultCounter := 0

	// loop to send the work and receive the work
send_receive_loop:
	for {
		select {
		case workChan <- string(leavesData[jobCounter]):
			jobCounter = jobCounter + 1
			if jobCounter == dataSize {
				close(workChan)
				break send_receive_loop
			}
		case workerResult := <-resultChan:
			if workerResult.err != nil {
				fetchInclusionResult.Errs = append(fetchInclusionResult.Errs, workerResult.err)
				fetchInclusionResult.FailedLeaves = append(fetchInclusionResult.FailedLeaves, workerResult.failedLeafData)
				fetchInclusionResult.FailedLeavesName = append(fetchInclusionResult.FailedLeavesName, workerResult.leafName)
			} else {
				// if no err, add the poi to the result
				fetchInclusionResult.PoIs[workerResult.leafName] = workerResult.PoI
			}
			resultCounter = resultCounter + 1
		}
	}

	// loop to receive the remaining results
	if resultCounter != dataSize {
		for {
			workerResult := <-resultChan
			if workerResult.err != nil {
				fetchInclusionResult.Errs = append(fetchInclusionResult.Errs, workerResult.err)
				fetchInclusionResult.FailedLeaves = append(fetchInclusionResult.FailedLeaves, workerResult.failedLeafData)
				fetchInclusionResult.FailedLeavesName = append(fetchInclusionResult.FailedLeavesName, workerResult.leafName)
			} else {
				// if no err, add the poi to the result
				fetchInclusionResult.PoIs[workerResult.leafName] = workerResult.PoI
			}
			resultCounter = resultCounter + 1
			if resultCounter == dataSize {
				close(resultChan)
				return fetchInclusionResult
			}
		}
	}
	// might not be reached
	return fetchInclusionResult
}
