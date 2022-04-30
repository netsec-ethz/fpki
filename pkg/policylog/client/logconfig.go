package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// LogClientConfig: config for a log client
type LogClientConfig struct {
	// target tree ID
	// for log client, normally there will only be one tree
	TreeId int64 `json:",omitempty"`

	// address of the rpc server
	RPCAddress            string `json:",omitempty"`
	MaxReceiveMessageSize int    `json:",omitempty"`

	// path to store the output from log client (now support SPT)
	OutPutPath string `json:",omitempty"`

	// path to read pre-RPC from PCA
	RPCPath string `json:",omitempty"`

	// number of workers
	NumOfWorker int `json:",omitempty"`
}

// SaveLogClientConfigToFile: save log client config to file
func SaveLogClientConfigToFile(config *LogClientConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveLogClientConfigToFile | WriteFile | %w", err)
	}
	return nil
}

// ReadLogClientConfigFromFile: read log client config from file
func ReadLogClientConfigFromFile(config *LogClientConfig, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("ReadLogClientConfigFromFile | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), config)
	if err != nil {
		return fmt.Errorf("ReadLogClientConfigFromFile | Unmarshal | %w", err)
	}

	return nil
}
