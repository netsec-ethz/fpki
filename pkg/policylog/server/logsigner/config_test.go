package logsigner

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestConfig: Write config to file -> read config from file -> compare
func TestConfig(t *testing.T) {
	config := &LogSignerConfig{
		RpcEndpoint:                    "localhost:8092",
		HttpEndpoint:                   "localhost:8093",
		HealthzTimeoutInSec:            5,
		QuotaSystem:                    "mysql",
		StorageSystem:                  "mysql",
		SequencerIntervalFlagInMillSec: 100,
		BatchSizeFlag:                  1000,
		NumSeqFlag:                     10,
		SequencerGuardWindowFlagInSec:  0,
		ForceMaster:                    true,
		EtcdHTTPService:                "trillian-logsigner-http",
		LockDir:                        "/test/multimaster",
		QuotaIncreaseFactor:            0,
		PreElectionPauseInSec:          1,
		MasterHoldIntervalInSec:        60,
		MasterHoldJitterInSec:          120,
	}

	tempFile := path.Join(os.TempDir(), "logsigner_config.json")
	defer os.Remove(tempFile)

	err := SaveLogSignerConfigToFile(config, tempFile)
	require.NoError(t, err)

	config_ := &LogSignerConfig{}
	err = ReadLogSignerConfigFromFile(config_, tempFile)
	require.NoError(t, err)

	require.Equal(t, config, config_)
}
