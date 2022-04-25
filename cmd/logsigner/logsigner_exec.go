package main

import (
	logSigner "github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
)

func main() {
	logSigner.PLCreateLogSigner("config/logsigner_config")
}
