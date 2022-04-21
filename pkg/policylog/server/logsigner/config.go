package logsigner

import (
	"encoding/json"
	"io/ioutil"
)

type LogSignerConfig struct {
	// "rpc_endpoint", "localhost:8092", "Endpoint for RPC requests (host:port)"
	RpcEndpoint string `json:"RpcEndpoint",omitempty`

	// "http_endpoint", "localhost:8093", "Endpoint for HTTP metrics (host:port, empty means disabled)"
	HttpEndpoint string `json:"HttpEndpoint",omitempty`

	// "tls_cert_file", "", "Path to the TLS server certificate. If unset, the server will use unsecured connections."
	TlsCertFile string `json:"TlsCertFile",omitempty`

	// "tls_key_file", "", "Path to the TLS server key. If unset, the server will use unsecured connections."
	TlsKeyFile string `json:"TlsKeyFile",omitempty`

	// "healthz_timeout", time.Second*5, "Timeout used during healthz checks"
	HealthzTimeoutInSec int `json:"HealthzTimeoutInSec",omitempty`

	// "quota_system", "mysql"
	QuotaSystem string `json:"QuotaSystem",omitempty`

	// "storage_system", "mysql"
	StorageSystem string `json:"StorageSystem",omitempty`

	// "config", "", "Config file containing flags, file contents can be overridden by command line flags"
	ConfigFile string `json:"ConfigFile",omitempty`

	// "sequencer_interval", 100*time.Millisecond, "Time between each sequencing pass through all logs"
	SequencerIntervalFlagInMillSec int `json:"SequencerIntervalFlagInMillSec",omitempty`

	// "batch_size", 1000, "Max number of leaves to process per batch"
	BatchSizeFlag int `json:"batchSizeFlag",omitempty`

	// "num_sequencers", 10, "Number of sequencer workers to run in parallel"
	NumSeqFlag int `json:"numSeqFlag",omitempty`

	// "sequencer_guard_window", 0, "If set, the time elapsed before submitted leaves are eligible for sequencing"
	SequencerGuardWindowFlagInSec int `json:"sequencerGuardWindowFlag",omitempty`

	// "force_master", false, "If true, assume master for all logs"
	ForceMaster bool `json:"forceMaster",omitempty`

	// "etcd_http_service", "trillian-logsigner-http", "Service name to announce our HTTP endpoint under"
	EtcdHTTPService string `json:"etcdHTTPService",omitempty`

	// "lock_file_path", "/test/multimaster", "etcd lock file directory path"
	LockDir string `json:"lockDir",omitempty`

	//"quota_increase_factor", log.QuotaIncreaseFactor,
	//	"Increase factor for tokens replenished by sequencing-based quotas (1 means a 1:1 relationship between sequenced leaves and replenished tokens)."+
	//		"Only effective for --quota_system=etcd."
	QuotaIncreaseFactor float64 `json:"quotaIncreaseFactor",omitempty`

	// "pre_election_pause", 1*time.Second, "Maximum time to wait before starting elections"
	PreElectionPauseInSec int `json:"preElectionPauseInSec",omitempty`

	// "master_hold_interval", 60*time.Second, "Minimum interval to hold mastership for"
	MasterHoldIntervalInSec int `json:"masterHoldIntervalInSec",omitempty`

	//"master_hold_jitter", 120*time.Second, "Maximal random addition to --master_hold_interval"
	MasterHoldJitterInSec int `json:"masterHoldJitterInSec",omitempty`

	// "cpuprofile", "", "If set, write CPU profile to this file"
	CpuProfile string `json:"CpuProfile",omitempty`

	// "memprofile", "", "If set, write memory profile to this file"
	MemProfile string `json:"MemProfile",omitempty`
}

func (config *LogSignerConfig) Equal(config_ *LogSignerConfig) bool {
	if config.RpcEndpoint == config_.RpcEndpoint &&
		config.HttpEndpoint == config_.HttpEndpoint &&
		config.TlsCertFile == config_.TlsCertFile &&
		config.TlsKeyFile == config_.TlsKeyFile &&
		config.HealthzTimeoutInSec == config_.HealthzTimeoutInSec &&
		config.QuotaSystem == config_.QuotaSystem &&
		config.StorageSystem == config_.StorageSystem &&
		config.ConfigFile == config_.ConfigFile &&
		config.SequencerIntervalFlagInMillSec == config_.SequencerIntervalFlagInMillSec &&
		config.BatchSizeFlag == config_.BatchSizeFlag &&
		config.NumSeqFlag == config_.NumSeqFlag &&
		config.SequencerGuardWindowFlagInSec == config_.SequencerGuardWindowFlagInSec &&
		config.ForceMaster == config_.ForceMaster &&
		config.EtcdHTTPService == config_.EtcdHTTPService &&
		config.LockDir == config_.LockDir &&
		config.QuotaIncreaseFactor == config_.QuotaIncreaseFactor &&
		config.PreElectionPauseInSec == config_.PreElectionPauseInSec &&
		config.MasterHoldIntervalInSec == config_.MasterHoldIntervalInSec &&
		config.MasterHoldJitterInSec == config_.MasterHoldJitterInSec &&
		config.CpuProfile == config_.CpuProfile &&
		config.MemProfile == config_.MemProfile {
		return true
	}
	return false
}

func SaveLogSignerConfigToFile(config *LogSignerConfig, configPath string) error {
	bytes, err := json.MarshalIndent(config, "", " ")
	err = ioutil.WriteFile(configPath, bytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

func ReadLogSignerConfigFromFile(config *LogSignerConfig, configPath string) error {
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
