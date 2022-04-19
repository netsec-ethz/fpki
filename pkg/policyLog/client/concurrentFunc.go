package logClient

import (
	"context"
	base64 "encoding/base64"
	"github.com/google/trillian"
	"github.com/transparency-dev/merkle/rfc6962"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

// TODO: panic: send on closed channel

// this file contains multi-thread versions of the "Add_leaf" and "Retrive_Proof"
// the speed is 4-5 times faster than the single thread version (if number of worker > 5)

// func for single worker to add a leaf
func worker_addLeaf(ctx context.Context, worker trillian.TrillianLogClient, workChan <-chan string, resultChan chan<- error, treeId int64) {
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

		// return the result (err)
		resultChan <- err
	}
}

// Queue a list of leaves
func (c *PL_LogClient) AddLeaves(ctx context.Context, data [][]byte) error {
	// channels to workers
	workChan := make(chan string)

	// channels from worker, contains results
	resultChan := make(chan error)

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
		case err := <-resultChan:
			if err != nil {
				// if error is detected, close the channel and return (maybe close() is not necessary?)
				close(workChan)
				close(resultChan)
				return err
			}

			resultCounter = resultCounter + 1
			if resultCounter == dataSize {
				// if all the job is finished; May not be called
				close(resultChan)
				return nil
			}
		}
	}

	// loop to receive the remaining results
	if resultCounter != dataSize {
		for {
			err := <-resultChan
			if err != nil {
				close(resultChan)
				return err
			}

			resultCounter = resultCounter + 1
			if resultCounter == dataSize {
				close(resultChan)
				return nil
			}
		}
	}
	return nil
}

// func for a worker to fetch the inclusion
func worker_fetchInclusion(ctx context.Context, worker trillian.TrillianLogClient, workChan <-chan string, resultChan chan<- FetchInclusionResult, treeId int64, treeSize int64) {
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

		// init result
		result := &PoIAndSTH{}

		for {
			// get result
			resp, err := worker.GetInclusionProofByHash(ctx, request)

			// if the leaf is not found -> try later
			if err != nil && status.Code(err) == codes.NotFound {
				time.Sleep(10 * time.Millisecond)
				continue
			} else if err != nil {
				// send err back
				resultStruc := FetchInclusionResult{err: err}
				resultChan <- resultStruc
				return
			} else if len(resp.Proof) > 0 {
				// when query succeeds
				result.PoIs = resp.Proof

				// marshall the log root (Signed Tree Head)
				if err := result.STH.UnmarshalBinary(resp.SignedLogRoot.LogRoot); err != nil {
					resultStruc := FetchInclusionResult{err: err}
					resultChan <- resultStruc
					return
				}

				// hash to get the SPT fileName
				rpcHash := rfc6962.DefaultHasher.HashLeaf([]byte(leafData))
				leafName := base64.URLEncoding.EncodeToString(rpcHash)

				resultStruc := FetchInclusionResult{
					leafName: leafName,
					PoI:      result,
					err:      nil,
				}

				// send back
				resultChan <- resultStruc
				break
			}
		}
	}
}

// fetch inclusion proof for one leaf
// similar to previous func
func (c *PL_LogClient) FetchInclusions(ctx context.Context, data [][]byte) (map[string]*PoIAndSTH, error) {

	workChan := make(chan string)
	resultChan := make(chan FetchInclusionResult)

	for i := 0; i < len(c.worker); i++ {
		go worker_fetchInclusion(ctx, c.worker[i], workChan, resultChan, c.treeId, c.currentTreeSize)
	}

	dataSize := len(data)
	jobCounter := 0
	resultCounter := 0

	resultMap := map[string]*PoIAndSTH{}

	// loop to send the work and receive the work
send_receive_loop:
	for {
		select {
		case workChan <- string(data[jobCounter]):
			jobCounter = jobCounter + 1
			if jobCounter == dataSize {
				close(workChan)
				break send_receive_loop
			}
		case result := <-resultChan:
			if result.err != nil {
				close(workChan)
				close(resultChan)
				return nil, result.err
			}
			resultCounter = resultCounter + 1
			resultMap[result.leafName] = result.PoI
			if resultCounter == dataSize {
				close(resultChan)
				return resultMap, nil
			}
		}
	}

	// loop to receive the remaining results
	if resultCounter != dataSize {
		for {
			result := <-resultChan
			if result.err != nil {
				close(resultChan)
				return nil, result.err
			}

			resultCounter = resultCounter + 1
			resultMap[result.leafName] = result.PoI
			if resultCounter == dataSize {
				close(resultChan)
				return resultMap, nil
			}
		}
	}
	return resultMap, nil
}
