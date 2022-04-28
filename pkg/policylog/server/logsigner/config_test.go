package logsigner

import (
	"os"
	"path"
	"testing"

	"github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	config := &logsigner.LogSignerConfig{
		RpcEndpoint:                    "localhost:8092",
		HttpEndpoint:                   "localhost:8093",
		TlsCertFile:                    "",
		TlsKeyFile:                     "",
		HealthzTimeoutInSec:            5,
		QuotaSystem:                    "mysql",
		StorageSystem:                  "mysql",
		ConfigFile:                     "",
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
		CpuProfile:                     "",
		MemProfile:                     "",
	}

	tempFile := path.Join(os.TempDir(), "logsigner_config.json")
	defer os.Remove(tempFile)

	err := logsigner.SaveLogSignerConfigToFile(config, tempFile)
	require.NoError(t, err)

	config_ := &logsigner.LogSignerConfig{}
	err = logsigner.ReadLogSignerConfigFromFile(config_, tempFile)
	require.NoError(t, err)

	require.Equal(t, config, config_)
}
