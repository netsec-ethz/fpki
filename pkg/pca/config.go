package pca

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// PCAConfig: configuration of the pca
type PCAConfig struct {
	CAName       string                   `json:",omitempty"`
	CTLogServers []CTLogServerEntryConfig `json:",omitempty"`
	KeyPEM       []byte                   `json:",omitempty"`
	CertJSON     []byte                   `json:",omitempty"`
}

type CTLogServerEntryConfig struct {
	Name         string `json:",omitempty"`
	URL          string `json:",omitempty"`
	PublicKeyDER []byte `json:",omitempty"` // DER-encoded SubjectPublicKeyInfo object.
	//                                         See ctx509.MarshalPKIXPublicKey
}

// SaveConfigToFile: save PCA config to file
func SaveConfigToFile(config *PCAConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", "   ")
	if err != nil {
		return fmt.Errorf("SaveConfigToFile | Marshal | %w", err)
	}

	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveConfigToFile | WriteFile | %w", err)
	}

	return nil
}

// ReadConfigFromFile: Read PCA config from config
func ReadConfigFromFile(config *PCAConfig, configPath string) error {
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
