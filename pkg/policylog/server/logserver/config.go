package logserver

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// LogServerConfig: config for log server
type LogServerConfig struct {
	// "rpc_endpoint", "localhost:8090", "Endpoint for RPC requests (host:port)"
	RpcEndpoint string `json:",omitempty"`

	// "http_endpoint", "localhost:8091", "Endpoint for HTTP metrics (host:port, empty means disabled)"
	HttpEndpoint string `json:",omitempty"`

	// "healthz_timeout", time.Second*5, "Timeout used during healthz checks"
	HealthzTimeout int `json:",omitempty"`

	// "tls_cert_file", "", "Path to the TLS server certificate. If unset, the server will use unsecured connections."
	TlsCertFile string `json:",omitempty"`

	// "tls_key_file", "", "Path to the TLS server key. If unset, the server will use unsecured connections."
	TlsKeyFile string `json:",omitempty"`

	// "etcd_service", "trillian-logserver", "Service name to announce ourselves under"
	EtcdService string `json:",omitempty"`

	// "etcd_http_service", "trillian-logserver-http", "Service name to announce our HTTP endpoint under"
	EtcdHTTPService string `json:",omitempty"`

	// "quota_system", "mysql"
	QuotaSystem string `json:",omitempty"`

	// "quota_dry_run", false, "If true no requests are blocked due to lack of tokens"
	QuotaDryRun bool `json:",omitempty"`

	// "storage_system", "mysql"
	StorageSystem string `json:",omitempty"`

	// "tree_gc", true, "If true, tree garbage collection (hard-deletion) is periodically performed"
	TreeGCEnabled bool `json:",omitempty"`

	// "tree_delete_threshold", serverutil.DefaultTreeDeleteThreshold, "Minimum period a tree has to remain deleted before being hard-deleted"
	TreeDeleteThresholdInHour int `json:",omitempty"`

	// "tree_delete_min_run_interval", serverutil.DefaultTreeDeleteMinInterval, "Minimum interval between tree garbage collection sweeps. Actual runs happen randomly between [minInterval,2*minInterval)."
	TreeDeleteMinRunIntervalInHour int `json:",omitempty"`

	// "tracing", false, "If true opencensus Stackdriver tracing will be enabled. See https://opencensus.io/."
	Tracing bool `json:",omitempty"`

	// "tracing_project_id", "", "project ID to pass to stackdriver. Can be empty for GCP, consult docs for other platforms."
	TracingProjectID string `json:",omitempty"`

	// "tracing_percent", 0, "Percent of requests to be traced. Zero is a special case to use the DefaultSampler"
	TracingPercent int `json:",omitempty"`

	// "config", "", "Config file containing flags, file contents can be overridden by command line flags"
	ConfigFile string `json:",omitempty"`

	// Profiling related flags.
	// "cpuprofile", "", "If set, write CPU profile to this file"
	CpuProfile string `json:",omitempty"`

	// "memprofile", "", "If set, write memory profile to this file"
	MemProfile string `json:",omitempty"`
}

// SaveLogConfigToFile: Save log server config to file
func SaveLogConfigToFile(config *LogServerConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveLogConfigToFile | WriteFile | %w", err)
	}

	return nil
}

// ReadLogConfigFromFile: Read log server config from file
func ReadLogConfigFromFile(config *LogServerConfig, configPath string) error {
	file, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("ReadLogSignerConfigFromFile | ReadFile | %w", err)
	}

	err = json.Unmarshal([]byte(file), config)
	if err != nil {
		return fmt.Errorf("ReadLogSignerConfigFromFile | Unmarshal | %w", err)
	}

	return nil
}
