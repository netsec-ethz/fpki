package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// marshall structure to bytes, and store them in a file
func JsonStrucToFile(struc interface{}, filePath string) error {
	bytes, err := JsonStrucToBytes(struc)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

// check data type;
func JsonStrucToBytes(struc interface{}) ([]byte, error) {
	switch struc.(type) {
	case *RCSR:
		break
	case *RPC:
		break
	case SPT:
		break
	case *SPRT:
		break
	case *trillian.Proof:
		break
	case *types.LogRootV1:
		break
	default:
		return nil, fmt.Errorf("Structure not supported yet!")
	}

	bytes, err := json.MarshalIndent(struc, "", " ")
	return bytes, err
}

//--------------------------------------------------------------------------------
//                    Bytes to strucs
//--------------------------------------------------------------------------------

func JsonBytesToSPT(sptBytes []byte) (*SPT, error) {
	result := &SPT{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func JsonBytesToRPC(rpcBytes []byte) (*RPC, error) {
	result := &RPC{}

	err := json.Unmarshal(rpcBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func JsonBytesToPoI(poiBytes []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(poiBytes, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func JsonBytesToLogRoot(logRootBytes []byte) (*types.LogRootV1, error) {
	result := &types.LogRootV1{}

	err := json.Unmarshal(logRootBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func JsonBytesToProof(proofBytes []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(proofBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

//--------------------------------------------------------------------------------
//                               File to strucs
//--------------------------------------------------------------------------------

func JsonFileToRPC(struc *RPC, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), struc)
	if err != nil {
		return err
	}

	return nil
}

func JsonFileToSPT(struc *SPT, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), struc)
	if err != nil {
		return err
	}

	return nil
}
