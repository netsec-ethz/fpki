package main

import (
	"github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	logserver.PLCreateLogServer("logserver_config.json")
}
