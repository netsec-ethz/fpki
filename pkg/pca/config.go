package pca

import (
	"encoding/json"
	"io/ioutil"
)

// configuration of the pca
type PCAConfig struct {
	CAName string `json:"CAName",omitempty`

	// path to store the pca's key
	KeyPath string `json:"KeyPath",omitempty`

	// PCA's output path; sends RPC
	OutputPath string `json:"OutputPath",omitempty`

	// policy log's output path; receives SPT
	PolicyLogOutputPath string `json:"PolicyLogOutputPath",omitempty`
}

func SaveConfigToFile(config *PCAConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReadConfigFromFile(config *PCAConfig, configPath string) error {
	bytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(bytes), config)
	if err != nil {
		return err
	}
	return nil
}
