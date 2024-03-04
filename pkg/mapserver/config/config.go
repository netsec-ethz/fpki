package config

import (
	"encoding/json"
	"io/ioutil"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type Config struct {
	CTLogServerURLs    []string
	DBConfig           *db.Configuration
	CertificatePemFile string // A X509 pem certificate
	PrivateKeyPemFile  string // A RSA pem key
	HttpAPIPort        int

	UpdateAt    util.TimeOfDayWrap
	UpdateTimer util.DurationWrap
}

func ReadConfigFromFile(filePath string) (*Config, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// JSON to Config.
	c := &Config{}
	err = json.Unmarshal(data, c)

	return c, err
}

func WriteConfigurationToFile(filePath string, config *Config) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, data, 0644)
}
