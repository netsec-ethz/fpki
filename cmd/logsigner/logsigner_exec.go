package main

import (
	"github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
)

func main() {
	logsigner.CreateLogSigner("./config/logsigner_config.json")
}
