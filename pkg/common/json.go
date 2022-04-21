package common

import (
	"encoding/json"
	"fmt"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"io/ioutil"
)

// marshall structure to bytes, and store them in a file
func Json_StrucToFile(struc interface{}, filePath string) error {
	bytes, err := Json_StrucToBytes(struc)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

// check data type; type cast might not be necessary (?)
func Json_StrucToBytes(struc interface{}) ([]byte, error) {
	switch struc.(type) {
	case *RCSR:
		break
	case *RPC:
		break
	case *SPT:
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

func Json_BytesToSPT(sptBytes []byte) (*SPT, error) {
	result := &SPT{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Json_BytesToRPC(sptBytes []byte) (*RPC, error) {
	result := &RPC{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Json_BytesToPoI(poi []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(poi, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func Json_BytesToLogRoot(sptBytes []byte) (*types.LogRootV1, error) {
	result := &types.LogRootV1{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Json_BytesToProof(sptBytes []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

//--------------------------------------------------------------------------------
//                               File to strucs
//--------------------------------------------------------------------------------

func Json_FileToRPC(struc *RPC, filePath string) error {
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

func Json_FileToSPT(struc *SPT, filePath string) error {
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
