package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// JsonStrucToFile: marshall structure to bytes, and store them in a file
func JsonStrucToFile(struc interface{}, filePath string) error {
	bytes, err := JsonStrucToBytes(struc)
	if err != nil {
		return fmt.Errorf("JsonStrucToFile | JsonStrucToBytes | %w", err)
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("JsonStrucToFile | WriteFile | %w", err)
	}
	return nil
}

// JsonStrucToBytes: marshall json to bytes
func JsonStrucToBytes(struc interface{}) ([]byte, error) {
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
		return nil, fmt.Errorf("JsonStrucToBytes | Structure not supported yet!")
	}

	bytes, err := json.MarshalIndent(struc, "", " ")
	if err != nil {
		return nil, fmt.Errorf("JsonStrucToBytes | MarshalIndent | %w", err)
	}
	return bytes, nil
}

//--------------------------------------------------------------------------------
//                               Bytes to strucs
//--------------------------------------------------------------------------------
// JsonBytesToPoI: bytes -> PoI in json
func JsonBytesToPoI(poiBytes []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(poiBytes, result)
	if err != nil {
		return nil, fmt.Errorf("JsonBytesToPoI | Unmarshal | %w", err)
	}

	return result, nil
}

// JsonBytesToLogRoot: Bytes -> log root in json
func JsonBytesToLogRoot(logRootBytes []byte) (*types.LogRootV1, error) {
	result := &types.LogRootV1{}

	err := json.Unmarshal(logRootBytes, result)
	if err != nil {
		return nil, fmt.Errorf("JsonBytesToLogRoot | Unmarshal | %w", err)
	}
	return result, nil
}

//--------------------------------------------------------------------------------
//                               File to strucs
//--------------------------------------------------------------------------------

// JsonFileToRPC: read json files and unmarshal it to Root Policy Certificate
func JsonFileToRPC(struc *RPC, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToRPC | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), struc)
	if err != nil {
		return fmt.Errorf("JsonFileToRPC | Unmarshal | %w", err)
	}

	return nil
}

// JsonFileToSPT: read json files and unmarshal it to Signed Policy Timestamp
func JsonFileToSPT(struc *SPT, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToSPT | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), struc)
	if err != nil {
		return fmt.Errorf("JsonFileToSPT | Unmarshal | %w", err)
	}

	return nil
}

// JsonFileToProof: read json files and unmarshal it to trillian proof
func JsonFileToProof(proof *trillian.Proof, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToProof | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), proof)
	if err != nil {
		return fmt.Errorf("JsonFileToProof | Unmarshal | %w", err)
	}
	return nil
}

// JsonFileToSTH: read json files and unmarshal it to Signed Tree Head
func JsonFileToSTH(struc *types.LogRootV1, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToSTH | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), struc)
	if err != nil {
		return fmt.Errorf("JsonFileToSTH | Unmarshal | %w", err)
	}
	return nil
}
