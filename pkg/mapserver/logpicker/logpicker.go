package logpicker

import (
	"fmt"
)

// LogPicker: A component which is responsible for collecting certificate from CT log, and update the cooresponding domain entries in db
type LogPicker struct {
	processorChan chan UpdateRequest
}

// NewLogPicker: return a new log picker
func NewLogPicker(processorChan chan UpdateRequest) *LogPicker {
	return &LogPicker{processorChan: processorChan}
}

// UpdateDomainFromLog: Fetch certificates from log,
func (logPicker *LogPicker) UpdateDomainFromLog(ctURL string, startIndex int64, endIndex int64, numOfWorker int) error {
	gap := (endIndex - startIndex) / int64(numOfWorker)
	resultChan := make(chan UpdateCertResult)
	for i := 0; i < numOfWorker-1; i++ {
		go workerThread(ctURL, startIndex+int64(i)*gap, startIndex+int64(i+1)*gap-1, resultChan, logPicker.processorChan)
	}
	// last work take charge of the rest of the queries
	// Because var "gap" might be rounded.
	go workerThread(ctURL, startIndex+int64(numOfWorker-1)*gap, endIndex, resultChan, logPicker.processorChan)

	effectedDomains := 0
	for i := 0; i < numOfWorker; i++ {
		newResult := <-resultChan
		if newResult.Err != nil {
			return fmt.Errorf("UpdateDomainFromLog | %w", newResult.Err)
		}
		effectedDomains = effectedDomains + newResult.effectedDomainsNum
	}

	close(resultChan)

	fmt.Println("total num: ", endIndex-startIndex)
	fmt.Println("total num of effected domains: ", effectedDomains)
	return nil
}
