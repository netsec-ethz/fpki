package logserver

import (
	"os"
	"path"
	"testing"
)

func Test_Config(t *testing.T) {

	config := &LogServerConfig{
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

	tempFile := path.Join(os.TempDir(), "logserver_config.json")
	defer os.Remove(tempFile)

	err := PLSaveLogConfigToFile(config, tempFile)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	config_ := &LogServerConfig{}
	err = PLReadLogConfigFromFile(config_, tempFile)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	if !config.Equal(config_) {
		t.Errorf("config Equal() error")
		return
	}

}
