package logserver

import (
	"encoding/json"
	"io/ioutil"
)

type LogServerConfig struct {
	// "rpc_endpoint", "localhost:8090", "Endpoint for RPC requests (host:port)"
	RpcEndpoint string `json:"rpcEndpoint",omitempty`

	// "http_endpoint", "localhost:8091", "Endpoint for HTTP metrics (host:port, empty means disabled)"
	HttpEndpoint string `json:"httpEndpoint",omitempty`

	// "healthz_timeout", time.Second*5, "Timeout used during healthz checks"
	HealthzTimeout int `json:"healthzTimeout",omitempty`

	// "tls_cert_file", "", "Path to the TLS server certificate. If unset, the server will use unsecured connections."
	TlsCertFile string `json:"tlsCertFile",omitempty`

	// "tls_key_file", "", "Path to the TLS server key. If unset, the server will use unsecured connections."
	TlsKeyFile string `json:"tlsKeyFile",omitempty`

	// "etcd_service", "trillian-logserver", "Service name to announce ourselves under"
	EtcdService string `json:"etcdService",omitempty`

	// "etcd_http_service", "trillian-logserver-http", "Service name to announce our HTTP endpoint under"
	EtcdHTTPService string `json:"etcdHTTPService",omitempty`

	// "quota_system", "mysql"
	QuotaSystem string `json:"quotaSystem",omitempty`

	// "quota_dry_run", false, "If true no requests are blocked due to lack of tokens"
	QuotaDryRun bool `json:"quotaDryRun",omitempty`

	// "storage_system", "mysql"
	StorageSystem string `json:"storageSystem",omitempty`

	// "tree_gc", true, "If true, tree garbage collection (hard-deletion) is periodically performed"
	TreeGCEnabled bool `json:"treeGCEnabled",omitempty`

	// "tree_delete_threshold", serverutil.DefaultTreeDeleteThreshold, "Minimum period a tree has to remain deleted before being hard-deleted"
	TreeDeleteThresholdInHour int `json:"treeDeleteThreshold",omitempty`

	// "tree_delete_min_run_interval", serverutil.DefaultTreeDeleteMinInterval, "Minimum interval between tree garbage collection sweeps. Actual runs happen randomly between [minInterval,2*minInterval)."
	TreeDeleteMinRunIntervalInHour int `json:"treeDeleteMinRunInterval",omitempty`

	// "tracing", false, "If true opencensus Stackdriver tracing will be enabled. See https://opencensus.io/."
	Tracing bool `json:"tracing",omitempty`

	// "tracing_project_id", "", "project ID to pass to stackdriver. Can be empty for GCP, consult docs for other platforms."
	TracingProjectID string `json:"tracingProjectID",omitempty`

	// "tracing_percent", 0, "Percent of requests to be traced. Zero is a special case to use the DefaultSampler"
	TracingPercent int `json:"tracingPercent",omitempty`

	// "config", "", "Config file containing flags, file contents can be overridden by command line flags"
	ConfigFile string `json:"configFile",omitempty`

	// Profiling related flags.
	// "cpuprofile", "", "If set, write CPU profile to this file"
	CpuProfile string `json:"cpuProfile",omitempty`

	// "memprofile", "", "If set, write memory profile to this file"
	MemProfile string `json:"memProfile",omitempty`
}

func (config *LogServerConfig) Equal(config_ *LogServerConfig) bool {
	if config.RpcEndpoint == config.RpcEndpoint &&
		config.HttpEndpoint == config.HttpEndpoint &&
		config.HealthzTimeout == config.HealthzTimeout &&
		config.TlsCertFile == config.TlsCertFile &&
		config.TlsKeyFile == config.TlsKeyFile &&
		config.EtcdService == config.EtcdService &&
		config.EtcdHTTPService == config.EtcdHTTPService &&
		config.QuotaSystem == config.QuotaSystem &&
		config.QuotaDryRun == config.QuotaDryRun &&
		config.StorageSystem == config.StorageSystem &&
		config.TreeGCEnabled == config.TreeGCEnabled &&
		config.TreeDeleteThresholdInHour == config.TreeDeleteThresholdInHour &&
		config.TreeDeleteMinRunIntervalInHour == config.TreeDeleteMinRunIntervalInHour &&
		config.Tracing == config.Tracing &&
		config.TracingProjectID == config.TracingProjectID &&
		config.TracingPercent == config.TracingPercent &&
		config.ConfigFile == config.ConfigFile &&
		config.CpuProfile == config.CpuProfile &&
		config.MemProfile == config.MemProfile {
		return true
	}
	return false
}

func PL_SaveLogConfigToFile(config *LogServerConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

func PL_ReadLogConfigFromFile(config *LogServerConfig, configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(file), config)
	if err != nil {
		return err
	}

	return nil
}
