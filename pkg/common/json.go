package common

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
)

func JsonBytesToPoI(poiBytesArray [][]byte) ([]*trillian.Proof, error) {
	// po, err := FromJSON(poiBytesArray)
	// if err != nil {
	// 	return nil, fmt.Errorf("JsonBytesToPoI | Unmarshal | %w", err)
	// }
	// result, ok := po.(*trilliantypes.LogRootV1)
	// if !ok {
	// 	return nil, fmt.Errorf("JsonFileToPoI | object is %T", po)
	// }

	// deleteme

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

// JSONToLogRoot: Bytes -> log root in json
func JSONToLogRoot(logRootBytes []byte) (*trilliantypes.LogRootV1, error) {
	po, err := FromJSON(logRootBytes)
	if err != nil {
		return nil, fmt.Errorf("JsonBytesToLogRoot | Unmarshal | %w", err)
	}
	result, ok := po.(*trilliantypes.LogRootV1)
	if !ok {
		return nil, fmt.Errorf("JsonFileToLogRoot | object is %T", po)
	}
	return result, nil
}

// JsonFileToRPC: read json files and unmarshal it to Root Policy Certificate
func JsonFileToRPC(filePath string) (*RPC, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToRPC | Unmarshal | %w", err)
	}

	o, ok := po.(*RPC)
	if !ok {
		return nil, fmt.Errorf("JsonFileToRPC | object is %T", po)
	}
	return o, nil
}

// JsonFileToSPT: read json files and unmarshal it to Signed Policy Timestamp
func JsonFileToSPT(filePath string) (*SPT, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSPT | Unmarshal | %w", err)
	}

	o, ok := po.(*SPT)
	if !ok {
		return nil, fmt.Errorf("JsonFileToSPT | object is %T", po)
	}
	return o, nil
}

// JsonFileToProof: read json files and unmarshal it to trillian proof
func JsonFileToProof(filePath string) (*trillian.Proof, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToProof | Unmarshal | %w", err)
	}

	o, ok := po.(*trillian.Proof)
	if !ok {
		return nil, fmt.Errorf("JsonFileToProof | object is %T", po)
	}
	return o, nil
}

// JsonFileToSTH: read json files and unmarshal it to Signed Tree Head
func JsonFileToSTH(filePath string) (*trilliantypes.LogRootV1, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSTH | Unmarshal | %w", err)
	}

	o, ok := po.(*trilliantypes.LogRootV1)
	if !ok {
		return nil, fmt.Errorf("JsonFileToSTH | object is %T", po)
	}
	return o, nil
}

// JsonFileToSTH reads a json file and unmarshals it to a Signed Policy.
func JsonFileToSP(filePath string) (*SP, error) {
	po, err := FromJSONFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("JsonFileToSP | Unmarshal | %w", err)
	}

	o, ok := po.(*SP)
	if !ok {
		err = fmt.Errorf("JsonFileToSP | object is %T", po)
	}
	return o, err
}

func ToJSON(o any) ([]byte, error) {
	r := struct {
		T string
		O any
	}{
		O: o,
	}
	// Find the internal type of the object to marshal.
	switch o := o.(type) {
	case *RCSR:
		r.T = "rcsr"
	case *RPC:
		r.T = "rpc"
	case *PCRevocation:
		r.T = "pcrevocation"
	case *SPT:
		r.T = "spt"
	case *SPRT:
		r.T = "sprt"
	case *SP:
		r.T = "sp"
	case *PSR:
		r.T = "psr"
	case *trillian.Proof:
		r.T = "trillian.Proof"
	case []*trillian.Proof:
		r.T = "[]trillian.Proof"
	case *trilliantypes.LogRootV1:
		r.T = "LogRootV1"
	default:
		return nil, fmt.Errorf("unrecognized type %T", o)
	}

	// Now Marshal the wrapper.
	d, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("wrapping marshalling of object: %w", err)
	}
	return d, nil
}

func FromJSON(data []byte) (any, error) {
	// Get only the type.
	typeOnly := struct {
		T string
	}{}
	if err := json.Unmarshal(data, &typeOnly); err != nil {
		return nil, fmt.Errorf("obtaining the wrapping type: %w", err)
	}

	switch typeOnly.T {
	case "rcsr":
		typeAndValue := struct {
			T string
			O *RCSR
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "rpc":
		typeAndValue := struct {
			T string
			O *RPC
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "spt":
		typeAndValue := struct {
			T string
			O *SPT
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "sprt":
		typeAndValue := struct {
			T string
			O *SPRT
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "sp":
		typeAndValue := struct {
			T string
			O *SP
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "psr":
		typeAndValue := struct {
			T string
			O *PSR
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "trillian.Proof":
		typeAndValue := struct {
			T string
			O *trillian.Proof
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "[]trillian.Proof":
		typeAndValue := struct {
			T string
			O []*trillian.Proof
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	case "LogRootV1":
		typeAndValue := struct {
			T string
			O *trilliantypes.LogRootV1
		}{}
		if err := json.Unmarshal(data, &typeAndValue); err != nil {
			return nil, fmt.Errorf("unmarshalling internal type: %w", err)
		}
		return typeAndValue.O, nil
	default:
		return nil, fmt.Errorf("unmarshalling internal type: bad type \"%s\"", typeOnly.T)
	}
}

// ToJSONFile serializes any supported type to a file, using JSON.
func ToJSONFile(s any, filePath string) error {
	bytes, err := ToJSON(s)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | ToJSON | %w", err)
	}

	err = ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("JsonStructToFile | WriteFile | %w", err)
	}
	return nil
}

func FromJSONFile(filePath string) (any, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return FromJSON(data)
}
