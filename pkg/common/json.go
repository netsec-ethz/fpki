package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/trillian"
	"github.com/google/trillian/types"
)

// JsonStructToFile: marshall structure to bytes, and store them in a file
func JsonStructToFile(s interface{}, filePath string) error {
	bytes, err := JsonStructToBytes(s)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | JsonStructToBytes | %w", err)
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | WriteFile | %w", err)
	}
	return nil
}

// JsonStructToBytes: marshall json to bytes
func JsonStructToBytes(s interface{}) ([]byte, error) {
	switch s.(type) {
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
	case *SP:
		break
	case *PSR:
		break
	case []byte:
		break
	case []*trillian.Proof:
		break
	default:
		return nil, fmt.Errorf("JsonStructToBytes | Structure not supported yet")
	}

	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("JsonStructToBytes | Marshal | %w", err)
	}
	return bytes, nil
}

// --------------------------------------------------------------------------------
//
//	Bytes to struct
//
// --------------------------------------------------------------------------------
// JsonBytesToPoI: bytes -> PoI in json
func JsonBytesToPoI(poiBytesArray [][]byte) ([]*trillian.Proof, error) {
	result := []*trillian.Proof{}

	for _, poiBytes := range poiBytesArray {
		newPOI := &trillian.Proof{}
		err := json.Unmarshal(poiBytes, newPOI)
		if err != nil {
			return nil, fmt.Errorf("JsonBytesToPoI | Unmarshal | %w", err)
		}
		result = append(result, newPOI)
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
//                               File to struct
//--------------------------------------------------------------------------------

// JsonFileToRPC: read json files and unmarshal it to Root Policy Certificate
func JsonFileToRPC(s *RPC, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToRPC | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), s)
	if err != nil {
		return fmt.Errorf("JsonFileToRPC | Unmarshal | %w", err)
	}

	return nil
}

// JsonFileToSPT: read json files and unmarshal it to Signed Policy Timestamp
func JsonFileToSPT(s *SPT, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToSPT | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), s)
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
func JsonFileToSTH(s *types.LogRootV1, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToSTH | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), s)
	if err != nil {
		return fmt.Errorf("JsonFileToSTH | Unmarshal | %w", err)
	}
	return nil
}

// JsonFileToSTH: read json files and unmarshal it to Signed Tree Head
func JsonFileToSP(s *SP, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("JsonFileToSP | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), s)
	if err != nil {
		return fmt.Errorf("JsonFileToSP | Unmarshal | %w", err)
	}
	return nil
}
