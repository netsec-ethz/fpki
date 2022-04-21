package main

import (
	logSigner "github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
)

func main() {
	logSigner.PL_CreateLogSigner("/Users/yongzhe/Desktop/fpki/config/policyLog/PL_logSignerConfig")
}
