package logserver

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConfig: Write config -> read config -> compare
func TestConfig(t *testing.T) {

	config := &LogServerConfig{
		RpcEndpoint:                    "localhost:8090",
		HttpEndpoint:                   "localhost:8091",
		HealthzTimeout:                 5,
		EtcdService:                    "trillian-logserver",
		EtcdHTTPService:                "trillian-logserver-http",
		QuotaSystem:                    "mysql",
		StorageSystem:                  "mysql",
		TreeGCEnabled:                  true,
		TreeDeleteThresholdInHour:      7 * 24,
		TreeDeleteMinRunIntervalInHour: 4,
	}

	tempFile := path.Join("./", "logserver_config.json")
	//defer os.Remove(tempFile)

	err := SaveLogConfigToFile(config, tempFile)
	require.NoError(t, err)

	config_ := &LogServerConfig{}
	err = ReadLogConfigFromFile(config_, tempFile)
	require.NoError(t, err)

	require.Equal(t, config, config_)

}
