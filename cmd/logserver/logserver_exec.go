package main

import (
	"github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	logserver.CreateLogServer("./config/logserver_config.json")
}
