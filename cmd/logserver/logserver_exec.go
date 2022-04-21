package main

import (
	logServer "github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	logServer.PL_CreateLogServer("/Users/yongzhe/Desktop/fpki/config/policyLog/PL_logConfig")
}
