package main

import (
	PL_logServer "PL_logServer.FPKI.github.com"
	"testing"
)

func Test_Config(t *testing.T) {

	config := &PL_logServer.PL_LogServerConfig{
		RpcEndpoint:                    "localhost:8090",
		HttpEndpoint:                   "localhost:8091",
		HealthzTimeout:                 5,
		TlsCertFile:                    "",
		TlsKeyFile:                     "",
		EtcdService:                    "trillian-logserver",
		EtcdHTTPService:                "trillian-logserver-http",
		QuotaSystem:                    "mysql",
		QuotaDryRun:                    false,
		StorageSystem:                  "mysql",
		TreeGCEnabled:                  true,
		TreeDeleteThresholdInHour:      7 * 24,
		TreeDeleteMinRunIntervalInHour: 4,
		Tracing:                        false,
		TracingProjectID:               "",
		TracingPercent:                 0,
		ConfigFile:                     "",
		CpuProfile:                     "",
		MemProfile:                     "",
	}

	err := PL_logServer.PL_saveLogConfigToFile(config, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/PL_logConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	config_ := &PL_logServer.PL_LogServerConfig{}
	err = PL_logServer.PL_ReadLogConfigFromFile(config_, "/Users/yongzhe/Desktop/fpki/config/policyLogConfig/PL_logConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !config.Equal(config_) {
		t.Errorf("config Equal() error")
		return
	}

}
