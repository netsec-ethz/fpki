package PL_LogClient

import (
	common "common.FPKI.github.com"
	"encoding/json"
	"io/ioutil"
)

// configuration of the client
type PL_AdminClientConfig struct {
	RpcMaxWaitingTimeInSec int    `json:"rpcMaxWaitingTimeInSec",omitempty`
	HashStrategy           string `json:"hashStrategy",omitempty`

	// name of the tree
	DisplayName string `json:"displayName",omitempty`

	// description of the tree
	Description string `json:"description",omitempty`

	// Interval after which a new signed root is produced despite no submissions; zero means never
	MaxRootDuration int `json:"maxRootDuration",omitempty`

	MaxReceiveMessageSize int    `json:"maxReceiveMessageSize",omitempty`
	LogAddress            string `json:"logAddress",omitempty`
	OutPutPath            string `json:"OutPutPath",omitempty`
}

func (config *PL_AdminClientConfig) Equal(config_ *PL_AdminClientConfig) bool {
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

func SaveConfigToFile(config *PL_AdminClientConfig, configPath string) error {
	return common.Json_WriteStrucToFile(config, configPath)
}

func Json_ReadConfigFromFile(config *PL_AdminClientConfig, filePath string) error {
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

type PL_LogClientConfig struct {
	TreeId                int64  `json:"TreeId",omitempty`
	RPCAddress            string `json:"RPCAddress",omitempty`
	MaxReceiveMessageSize int    `json:"MaxReceiveMessageSize",omitempty`
}

func (config *PL_LogClientConfig) Equal(config_ *PL_LogClientConfig) bool {
	if config.RPCAddress == config_.RPCAddress &&
		config.TreeId == config_.TreeId &&
		config.MaxReceiveMessageSize == config_.MaxReceiveMessageSize {
		return true
	}
	return false
}

func Json_ReadLogConfigFromFile(config *PL_LogClientConfig, filePath string) error {
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
