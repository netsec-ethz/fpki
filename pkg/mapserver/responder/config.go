package responder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// PCAConfig: configuration of the pca
type MapserverConfig struct {
	// path to store the pca's key
	KeyPath string `json:",omitempty"`
}

// SaveConfigToFile: save PCA config to file
func SaveConfigToFile(config *MapserverConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		return fmt.Errorf("SaveConfigToFile | MarshalIndent | %w", err)
	}

	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveConfigToFile | WriteFile | %w", err)
	}

	return nil
}

// ReadConfigFromFile: Read PCA config from config
func ReadConfigFromFile(config *MapserverConfig, configPath string) error {
	bytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("ReadConfigFromFile | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(bytes), config)
	if err != nil {
		return fmt.Errorf("ReadConfigFromFile | Unmarshal | %w", err)
	}

	return nil
}
