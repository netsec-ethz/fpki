package logsigner

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// LogSignerConfig: config for log signer
type LogSignerConfig struct {
	// "rpc_endpoint", "localhost:8092", "Endpoint for RPC requests (host:port)"
	RpcEndpoint string `json:",omitempty"`

	// "http_endpoint", "localhost:8093", "Endpoint for HTTP metrics (host:port, empty means disabled)"
	HttpEndpoint string `json:",omitempty"`

	// "healthz_timeout", time.Second*5, "Timeout used during healthz checks"
	HealthzTimeoutInSec int `json:",omitempty"`

	// "quota_system", "mysql"
	QuotaSystem string `json:",omitempty"`

	// "storage_system", "mysql"
	StorageSystem string `json:",omitempty"`

	// "sequencer_interval", 100*time.Millisecond, "Time between each sequencing pass through all logs"
	SequencerIntervalFlagInMillSec int `json:",omitempty"`

	// "batch_size", 1000, "Max number of leaves to process per batch"
	BatchSizeFlag int `json:",omitempty"`

	// "num_sequencers", 10, "Number of sequencer workers to run in parallel"
	NumSeqFlag int `json:",omitempty"`

	// "sequencer_guard_window", 0, "If set, the time elapsed before submitted leaves are eligible for sequencing"
	SequencerGuardWindowFlagInSec int `json:",omitempty"`

	// "force_master", false, "If true, assume master for all logs"
	ForceMaster bool `json:",omitempty"`

	// "etcd_http_service", "trillian-logsigner-http", "Service name to announce our HTTP endpoint under"
	EtcdHTTPService string `json:",omitempty"`

	// "lock_file_path", "/test/multimaster", "etcd lock file directory path"
	LockDir string `json:",omitempty"`

	//"quota_increase_factor", log.QuotaIncreaseFactor,
	//	"Increase factor for tokens replenished by sequencing-based quotas (1 means a 1:1 relationship between sequenced
	//      leaves and replenished tokens)."+
	//	"Only effective for --quota_system=etcd."
	QuotaIncreaseFactor float64 `json:",omitempty"`

	// "pre_election_pause", 1*time.Second, "Maximum time to wait before starting elections"
	PreElectionPauseInSec int `json:",omitempty"`

	// "master_hold_interval", 60*time.Second, "Minimum interval to hold mastership for"
	MasterHoldIntervalInSec int `json:",omitempty"`

	//"master_hold_jitter", 120*time.Second, "Maximal random addition to --master_hold_interval"
	MasterHoldJitterInSec int `json:",omitempty"`
}

// SaveLogSignerConfigToFile: Save log signer config from file
func SaveLogSignerConfigToFile(config *LogSignerConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		return fmt.Errorf("SaveLogSignerConfigToFile | MarshalIndent | %w", err)
	}

	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return fmt.Errorf("SaveLogSignerConfigToFile | WriteFile | %w", err)
	}
	return nil
}

// ReadLogSignerConfigFromFile: Read log signer config from file
func ReadLogSignerConfigFromFile(config *LogSignerConfig, configPath string) error {
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
