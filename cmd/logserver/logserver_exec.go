package main

import (
	logServer "github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	logServer.PL_CreateLogServer("../config/policyLog/logserver_config")
}
