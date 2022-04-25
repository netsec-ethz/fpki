package main

import (
	logServer "github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	logServer.PLCreateLogServer("config/logserver_config")
}
