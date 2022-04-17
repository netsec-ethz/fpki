package common

import (
	"encoding/json"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"io/ioutil"
)

func Json_WriteStrucToFile(struc interface{}, filePath string) error {
	file, err := json.MarshalIndent(struc, "", " ")
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filePath, file, 0644)
	if err != nil {
		return err
	}
	return nil
}

func Json_RPCBytesToBytes(rpc *RPC) ([]byte, error) {
	bytes, err := json.MarshalIndent(rpc, "", " ")
	return bytes, err
}

func Json_ProofToBytes(proof *trillian.Proof) ([]byte, error) {
	bytes, err := json.MarshalIndent(proof, "", " ")
	return bytes, err
}

func Json_SPTToBytes(spt *SPT) ([]byte, error) {
	bytes, err := json.MarshalIndent(spt, "", " ")
	return bytes, err
}

func Json_BytesToPoI(poi []byte) (*trillian.Proof, error) {
	result := &trillian.Proof{}

	err := json.Unmarshal(poi, result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func Json_BytesToSPT(sptBytes []byte) (*SPT, error) {
	result := &SPT{}

	err := json.Unmarshal(sptBytes, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func Json_LogRootToBytes(sth *types.LogRootV1) ([]byte, error) {
	bytes, err := json.MarshalIndent(sth, "", " ")
	return bytes, err
}

func Json_ReadRPCFromFile(struc *RPC, filePath string) error {
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

func Json_ReadSPTFromFile(struc *SPT, filePath string) error {
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
