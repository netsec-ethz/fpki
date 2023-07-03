package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type Config struct {
	UpdateTimer util.DurationWrap
	UpdateAt    util.TimeOfDayWrap
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
