package policyLog

import (
	"fmt"
	"github.com/google/trillian"
)

type PL_LogClient struct {
	client trillian.TrillianLogClient
	config *PL_Config
}

func PL_GetLogClient(configPath string) (*PL_LogClient, error) {

	config := &PL_Config{}
	err := Json_ReadConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("PL_GetLogClient | Json_ReadConfigFromFile | %s", err.Error())
	}

	// get conn
	conn, err := GetGRPCConn(config.MaxReceiveMessageSize, config.LogAddress)
	if err != nil {
		return nil, fmt.Errorf("PL_GetLogClient | Dial | %s", err.Error())
	}

	//defer conn.Close()
	logClient := trillian.NewTrillianLogClient(conn)

	client := PL_LogClient{
		client: logClient,
		config: config,
	}

	return &client, nil
}
