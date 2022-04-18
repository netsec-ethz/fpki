package main

import (
	logServer "logServer.FPKI.github.com"
	"testing"
)

func Test_Config(t *testing.T) {

	config := &logServer.LogServerConfig{
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

	err := logServer.PL_SaveLogConfigToFile(config, "/Users/yongzhe/Desktop/fpki/config/policyLog/PL_logConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	config_ := &logServer.LogServerConfig{}
	err = logServer.PL_ReadLogConfigFromFile(config_, "/Users/yongzhe/Desktop/fpki/config/policyLog/PL_logConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !config.Equal(config_) {
		t.Errorf("config Equal() error")
		return
	}

}
