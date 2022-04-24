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
	map_smt, err := InitSMT(628379840923)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	_, _ = map_smt.Update([]byte("foo"), []byte("bar"))

	// Generate a Merkle proof for foo=bar
	proof, _ := map_smt.Prove([]byte("fa"))
	root := map_smt.Root() // We also need the current tree root for the proof

	//fmt.Println(proof)
	//fmt.Println(root)

	// Verify the Merkle proof for foo=bar
	if smt.VerifyProof(proof, root, []byte("foo"), []byte("bar"), sha256.New()) {
		fmt.Println("Proof verification succeeded.")
	} else {
		fmt.Println("Proof verification failed.")
	}

	nameMap := map[string]string{}
	testNum := 10000

	for i := 0; i < testNum; i++ {
		nameMap[RandStringBytes(30)] = RandStringBytes(30)
	}

	start := time.Now()
	for k, v := range nameMap {
		map_smt.Update([]byte(k), []byte(v))
	}
	end := time.Now()
	fmt.Println(end.Sub(start))
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
