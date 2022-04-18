package types

import (
	"encoding/json"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"io/ioutil"
)

// Not sure whether reflection is needed
func Json_StrucToFile(struc interface{}, filePath string) error {
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

func Json_StrucToBytes(struc interface{}) ([]byte, error) {
	bytes, err := json.MarshalIndent(rcsr, "", " ")
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

//------------------------------------------------------------------------
//                             read from file
//------------------------------------------------------------------------

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
