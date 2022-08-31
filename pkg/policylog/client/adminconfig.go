package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// AdminClientConfig: configuration of the client
type AdminClientConfig struct {
	RpcMaxWaitingTimeInSec int    `json:",omitempty"`
	HashStrategy           string `json:",omitempty"`

	// name of the tree
	DisplayName string `json:",omitempty"`

	// description of the tree
	Description string `json:",omitempty"`

	// Interval after which a new signed root is produced despite no submissions; zero means never
	MaxRootDuration int `json:",omitempty"`

	MaxReceiveMessageSize int `json:",omitempty"`

	// address of the log server
	LogAddress string `json:",omitempty"`

	// path to store the output from admin client (now support tree config)
	OutPutPath string `json:",omitempty"`
}

// SaveAdminClientConfigToFile: save admin client's config to file
func SaveAdminClientConfigToFile(config *AdminClientConfig, configPath string) error {
	bytes, err := json.Marshal(config)
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveAdminClientConfigToFile | WriteFile | %w", err)
	}
	return nil
}

// ReadAdminClientConfigFromFile: read admin client config from file
func ReadAdminClientConfigFromFile(config *AdminClientConfig, filePath string) error {
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("ReadAdminClientConfigFromFile | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), config)
	if err != nil {
		return fmt.Errorf("ReadAdminClientConfigFromFile | Unmarshal | %w", err)
	}
	return nil
}
