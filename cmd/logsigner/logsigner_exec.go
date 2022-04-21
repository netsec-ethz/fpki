package main

import (
	logSigner "github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
)

func main() {
	logSigner.PL_CreateLogSigner("../config/policyLog/logsigner_config")
}
