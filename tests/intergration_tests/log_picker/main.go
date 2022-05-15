package main

import (
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
)

func main() {
	processorChan := make(chan logpicker.UpdateRequest)
	logPicker := logpicker.NewLogPicker(processorChan)
	certProcessor, err := logpicker.NewConsistentDB(20, processorChan)
	if err != nil {
		panic(err)
	}

	go certProcessor.StartWork()

	start := time.Now()
	err = logPicker.UpdateDomainFromLog("https://ct.googleapis.com/logs/argon2021", 1000000, 1000100, 5)
	if err != nil {
		panic(err)
	}
	end := time.Now()
	fmt.Println("time to update 100 certificates ", end.Sub(start))
}
