package main

import (
	"encoding/csv"
	"fmt"
	"io"

	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type line struct {
	fields []string // records
	number int      // line number
}

func (l line) String() string {
	return fmt.Sprintf("line %06d", l.number)
}

// csvSplitWorker is a processing stage that takes a CsvFile and outputs all its lines.
// The distribution is done in a staggered fan-out way to the next stages, so that each next
// stage i processes lines i, i+W, i+2W, etc (W being the number or next stages).
// TODO: instead of returning all lines, just return W lines and only read lines from file to
// memory when requested. This requires a change in pkg/pipeline.
type csvSplitWorker struct {
	*pip.Stage[util.CsvFile, line]
	lines   chan line
	lastErr error
}

func NewCsvSplitWorker(p *Processor) *csvSplitWorker {
	w := &csvSplitWorker{
		lines:   make(chan line, 1024), // Cache 1K lines.
		lastErr: nil,
	}

	lastOut := make([]line, 1)
	lastOutIndex := make([]int, 1) // The last parser used.
	var stillLinesToSend bool
	w.Stage = pip.NewStage[util.CsvFile, line](
		"csv_split",
		pip.WithMultiOutputChannels[util.CsvFile, line](p.NumWorkers),
		pip.WithProcessFunction(func(in util.CsvFile) ([]line, []int, error) {
			err := w.startReadingLines(in)
			if err == nil {
				err = pip.StreamOutput
			}
			return lastOut[:0], lastOutIndex[:0], err
		}),
		pip.WithOutputStreamingFunction[util.CsvFile](func(outs *[]line, outChs *[]int) error {
			*outs = lastOut
			*outChs = lastOutIndex
			(*outs)[0], stillLinesToSend = <-w.lines
			if !stillLinesToSend {
				*outs = (*outs)[:0]
				*outChs = (*outChs)[:0]
				p.stats.TotalFilesRead.Add(1)
				return nil
			}
			(*outChs)[0] = ((*outChs)[0] + 1) % p.NumWorkers
			return pip.StreamOutput
		}),
	)
	return w
}

func (w *csvSplitWorker) startReadingLines(f util.CsvFile) error {
	fileReader, err := f.Open()
	if err != nil {
		return err
	}

	r := csv.NewReader(fileReader)
	r.FieldsPerRecord = -1 // don't check number of fields
	var records []string
	w.lines = make(chan line, cap(w.lines))
	go func() {
		for lineNo := 1; ; lineNo++ {
			records, err = r.Read()
			if err != nil {
				if err != io.EOF {
					w.lastErr = err
				}
				break
			}
			w.lines <- line{
				fields: records,
				number: lineNo,
			}
		}
		close(w.lines)
		f.Close()
	}()

	return nil
}
