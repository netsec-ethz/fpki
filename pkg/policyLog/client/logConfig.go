package logClient

import (
	"encoding/json"
	"io/ioutil"
)

type PL_LogClientConfig struct {
	// target tree ID
	// for log client, normally there will only be one tree
	TreeId int64 `json:"TreeId",omitempty`

	// address of the rpc server
	RPCAddress            string `json:"RPCAddress",omitempty`
	MaxReceiveMessageSize int    `json:"MaxReceiveMessageSize",omitempty`

	// path to store the output from log client (now support SPT)
	OutPutPath string `json:"OutPutPath",omitempty`

	// path to read pre-RPC from PCA
	RPCPath string `json:"RPCPath",omitempty`

	// number of workers
	NumOfWorker int `json:"NumOfWorker",omitempty`
}

func (config *PL_LogClientConfig) Equal(config_ *PL_LogClientConfig) bool {
	if config.RPCAddress == config_.RPCAddress &&
		config.TreeId == config_.TreeId &&
		config.MaxReceiveMessageSize == config_.MaxReceiveMessageSize &&
		config.OutPutPath == config_.OutPutPath &&
		config.RPCPath == config_.RPCPath &&
		config.NumOfWorker == config_.NumOfWorker {
		return true
	}
	return false
}

func SaveLogClientConfigToFile(config *PL_LogClientConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReadLogClientConfigFromFile(config *PL_LogClientConfig, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), config)
	if err != nil {
		return err
	}

	return nil
}
