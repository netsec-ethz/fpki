package policyLog

import (
	common "common.FPKI.github.com"
	"encoding/json"
	"io/ioutil"
)

// configuration of the client
type PL_Config struct {
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
}

func (config *PL_Config) Equal(config_ *PL_Config) bool {
	if config.RpcMaxWaitingTimeInSec == config_.RpcMaxWaitingTimeInSec &&
		config.HashStrategy == config_.HashStrategy &&
		config.DisplayName == config_.DisplayName &&
		config.Description == config_.Description &&
		config.MaxRootDuration == config_.MaxRootDuration &&
		config.MaxReceiveMessageSize == config_.MaxReceiveMessageSize &&
		config.LogAddress == config_.LogAddress {
		return true
	}
	return false
}

func LoadConfigFromFile(configPath string) (*PL_Config, error) {
	return nil, nil
}

func SaveConfigToFile(config *PL_Config, configPath string) error {
	return common.Json_WriteStrucToFile(config, configPath)
}

func Json_ReadConfigFromFile(config *PL_Config, filePath string) error {
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
