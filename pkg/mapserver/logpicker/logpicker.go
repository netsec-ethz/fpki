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

// TODO(yongzhe): modify the error handling
// UpdateDomainFromLog: Fetch certificates from log,
func (logPicker *LogPicker) UpdateDomainFromLog(ctURL string, startIndex int64, endIndex int64, numOfWorker int, batchSize int) (int, int, error) {
	gap := (endIndex - startIndex) / int64(numOfWorker)
	resultChan := make(chan UpdateCertResult)
	for i := 0; i < numOfWorker-1; i++ {
		go workerThread(ctURL, startIndex+int64(i)*gap, startIndex+int64(i+1)*gap-1, resultChan, logPicker.processorChan, batchSize)
	}
	// last work take charge of the rest of the queries
	// Because var "gap" might be rounded.
	go workerThread(ctURL, startIndex+int64(numOfWorker-1)*gap, endIndex, resultChan, logPicker.processorChan, batchSize)

	effectedDomains := 0
	updatedCertsNum := 0
	for i := 0; i < numOfWorker; i++ {
		newResult := <-resultChan
		if newResult.Err != nil {
			return effectedDomains, updatedCertsNum, fmt.Errorf("UpdateDomainFromLog | %w", newResult.Err)
		}
		effectedDomains = effectedDomains + newResult.EffectedDomainsNum
		updatedCertsNum = updatedCertsNum + newResult.NumOfFetchedCert
	}

	close(resultChan)

	return effectedDomains, updatedCertsNum, nil
}
