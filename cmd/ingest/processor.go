package main

import (
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Processor is the processor that takes file names and process them into certificates
// inside the DB and SMT. It is composed of several different stages,
// described in the `start` method.
type Processor struct {
	pipeCsvToChains   *CsvToChainsPipeline
	pipeChainsToCerts *ChainsToCertificatesPipeline
	pipeDB            *updater.Manager
}

func NewProcessor() *Processor {
	p := &Processor{}

	return p
}

// resume starts the pipeline. The pipeline consists on the following transformations:
// - File to rows.
// - Row to certificate with chain.
// - Certificate with chain to certificate with immediate parent.
// This pipeline ends here, and it's picked up by other processor.
// Each stage (transformation) is represented by a goroutine spawned in this resume function.
// Each stage reads from the previous channel and outputs to the next channel.
// Each stage closes the channel it outputs to.
func (p *Processor) Resume() {
	p.resume()
}

func (p *Processor) Stop() {
	close(p.pipeCsvToChains.IncomingChan)
}

func (p *Processor) Wait() error {
	return p.pipeCsvToChains.Wait()
}

// AddGzFiles adds a CSV .gz file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddGzFiles(fileNames []string) {
	// Tell the certificate processor that we have these new files.
	p.pipeDB.Stats.TotalFiles.Add(int64(len(fileNames)))

	// Parse the file and send it to the CSV parser.
	for _, filename := range fileNames {
		p.pipeCsvToChains.IncomingChan <- (&util.GzFile{}).WithFile(filename)
	}
}

// AddGzFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddCsvFiles(fileNames []string) {
	// Tell the certificate processor that we have these new files.
	p.pipeDB.Stats.TotalFiles.Add(int64(len(fileNames)))
	// Parse the file and send it to the CSV parser.
	for _, filename := range fileNames {
		p.pipeCsvToChains.IncomingChan <- (&util.UncompressedFile{}).WithFile(filename)
	}
}

func (p *Processor) resume() {
	p.pipeCsvToChains.Resume()
}
