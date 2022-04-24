package smt_db

import (
	"crypto/sha256"
	"fmt"
	smt "github.com/celestiaorg/smt"
	"math/rand"
	"testing"
	"time"
)

func Test_SMT(t *testing.T) {
	// init a SMT
	map_smt, err := InitSMT(62837984045678923, []byte{})
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// insert one leaf
	_, _ = map_smt.Update([]byte("foo"), []byte("bar"))

	// Generate a Merkle proof for foo=bar
	proof, err := map_smt.Prove([]byte("foo"))
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	root := map_smt.Root()

	// Verify the Merkle proof for foo=bar
	if !smt.VerifyProof(proof, root, []byte("foo"), []byte("bar"), sha256.New()) {
		t.Errorf("false negative!")
		return
	}

	// Verify the Merkle proof for foo=bar
	if smt.VerifyProof(proof, root, []byte("foo"), []byte("baggr"), sha256.New()) {
		t.Errorf("false positive!")
		return
	}

	// update 3000 random leaves
	nameMap := map[string]string{}
	testNum := 3000

	for i := 0; i < testNum; i++ {
		nameMap[RandStringBytes(30)] = RandStringBytes(30)
	}

	start := time.Now()
	for k, v := range nameMap {
		map_smt.Update([]byte(k), []byte(v))
	}
	end := time.Now()
	fmt.Println("time to update 3,000 leaves: ", end.Sub(start))

	// check the correctness of proof
	start = time.Now()
	proof, _ = map_smt.Prove([]byte("foo"))
	root = map_smt.Root()
	end = time.Now()
	fmt.Println("time to fetch one proof: ", end.Sub(start))

	if !smt.VerifyProof(proof, root, []byte("foo"), []byte("bar"), sha256.New()) {
		t.Errorf("false negative!")
		return
	}

	if smt.VerifyProof(proof, root, []byte("foo"), []byte("bsaar"), sha256.New()) {
		t.Errorf("false positive!")
		return
	}

	// measure the time to store the updates
	start = time.Now()
	err = map_smt.SaveSMT()
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	end = time.Now()
	fmt.Println("time to save the updates: ", end.Sub(start))

	// measure the time to reload an existing tree
	start = time.Now()
	map_smt, err = InitSMT(62837984045678923, root)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	end = time.Now()
	fmt.Println("time to reload the tree: ", end.Sub(start))

	// check the correctness
	proof, _ = map_smt.Prove([]byte("foo"))
	root = map_smt.Root()
	if !smt.VerifyProof(proof, root, []byte("foo"), []byte("bar"), sha256.New()) {
		t.Errorf("false negative!")
		return
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
