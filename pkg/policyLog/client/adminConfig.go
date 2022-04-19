package logClient

import (
	"encoding/json"
	"io/ioutil"
)

// configuration of the client
type AdminClientConfig struct {
	RpcMaxWaitingTimeInSec int    `json:"rpcMaxWaitingTimeInSec",omitempty`
	HashStrategy           string `json:"hashStrategy",omitempty`

	// name of the tree
	DisplayName string `json:"displayName",omitempty`

	// description of the tree
	Description string `json:"description",omitempty`

	// Interval after which a new signed root is produced despite no submissions; zero means never
	MaxRootDuration int `json:"maxRootDuration",omitempty`

	MaxReceiveMessageSize int `json:"maxReceiveMessageSize",omitempty`

	// address of the log server
	LogAddress string `json:"logAddress",omitempty`

	// path to store the output from admin client (now support tree config)
	OutPutPath string `json:"OutPutPath",omitempty`
}

func (config *AdminClientConfig) Equal(config_ *AdminClientConfig) bool {
	if config.RpcMaxWaitingTimeInSec == config_.RpcMaxWaitingTimeInSec &&
		config.HashStrategy == config_.HashStrategy &&
		config.DisplayName == config_.DisplayName &&
		config.Description == config_.Description &&
		config.MaxRootDuration == config_.MaxRootDuration &&
		config.MaxReceiveMessageSize == config_.MaxReceiveMessageSize &&
		config.LogAddress == config_.LogAddress &&
		config.OutPutPath == config_.OutPutPath {
		return true
	}
	return false
}

func SaveAdminClientConfigToFile(config *AdminClientConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReadAdminClientConfigFromFile(config *AdminClientConfig, filePath string) error {
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
