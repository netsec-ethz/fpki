package common

import (
	"encoding/json"
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
