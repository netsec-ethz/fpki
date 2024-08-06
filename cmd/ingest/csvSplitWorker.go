package main

import (
	"encoding/csv"

	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type line struct {
	fields []string // records
	number int      // line number
}

type csvSplitWorker struct {
	*pip.Stage[util.CsvFile, line]

	csvFile util.CsvFile // closed at end of processing.
}

func NewCsvSplitWorker(p *Processor) *csvSplitWorker {
	w := &csvSplitWorker{}
	w.Stage = pip.NewStage[util.CsvFile, line](
		"csv_split",
		pip.WithMultiOutputChannels[util.CsvFile, line](p.NumWorkers),
		pip.WithSequentialOutputs[util.CsvFile, line](),
		pip.WithProcessFunctionMultipleOutputs(
			func(in util.CsvFile) ([]line, []int, error) {
				p.stats.TotalFilesRead.Add(1)
				w.csvFile = in
				lines, err := w.splitFile()
				channels := make([]int, len(lines))
				for i := 0; i < len(lines); i++ {
					channels[i] = i % p.NumWorkers
				}
				return lines, channels, err
			},
		),
		pip.WithOnNoMoreData[util.CsvFile, line](
			func() ([]line, []int, error) {
				err := w.csvFile.Close()
				return nil, nil, err
			},
		),
	)
	return w
}

func (w *csvSplitWorker) splitFile() ([]line, error) {
	fileReader, err := w.csvFile.Open()
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(fileReader)
	r.FieldsPerRecord = -1 // don't check number of fields
	records, err := r.ReadAll()

	// Convert records to lines (cast each line).
	lines := make([]line, len(records))
	for i, l := range records {
		lines[i] = line{
			fields: l,
			number: i + 1,
		}
	}

	return lines, err
}
