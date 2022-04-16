package main

import (
	PL_logSigner "PL_logSigner.FPKI.github.com"
	"testing"
)

func Test_Config(t *testing.T) {
	config := &PL_logSigner.PL_LogSignerConfig{
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
		ForceMaster:                    false,
		EtcdHTTPService:                "trillian-logsigner-http",
		LockDir:                        "/test/multimaster",
		QuotaIncreaseFactor:            0,
		PreElectionPauseInSec:          1,
		MasterHoldIntervalInSec:        60,
		MasterHoldJitterInSec:          120,
		CpuProfile:                     "",
		MemProfile:                     "",
	}

	err := PL_logSigner.PL_saveLogSignerConfigToFile(config, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/PL_logSignerConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	config_ := &PL_logSigner.PL_LogSignerConfig{}
	err = PL_logSigner.PL_ReadLogSignerConfigFromFile(config_, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/PL_logSignerConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !config.Equal(config_) {
		t.Errorf("config Equal() error")
		return
	}

}
