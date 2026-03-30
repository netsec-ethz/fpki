package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"

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
	lines            chan line  // Created once per file.
	done             chan error // Created once per file.
	skipMissingFiles bool
}

func NewCsvSplitWorker(p *Processor) *csvSplitWorker {
	w := &csvSplitWorker{
		skipMissingFiles: p.SkipMissing,
	}

	lastOut := make([]line, 1)
	lastOutIndex := make([]int, 1) // The last parser used.
	var stillLinesToSend bool
	w.Stage = pip.NewStage[util.CsvFile, line](
		"csv_split",
		pip.WithProcessFunction(func(in util.CsvFile) ([]line, []int, error) {
			err := w.startReadingLines(in)
			if err == nil {
				err = pip.StreamOutput
			}
			// Return the cached storage, even if empty.
			return lastOut[:0], lastOutIndex[:0], err
		}),
		pip.WithOutputStreamingFunction[util.CsvFile](func(outs *[]line, outChs *[]int) error {
			*outs = lastOut
			*outChs = lastOutIndex
			(*outs)[0], stillLinesToSend = <-w.lines
			if !stillLinesToSend {
				*outs = (*outs)[:0]
				*outChs = (*outChs)[:0]
				err := <-w.done
				if err == nil {
					p.Manager.Stats.TotalFilesRead.Add(1)
				}
				return err
			}
			return pip.StreamOutput
		}),
	)
	return w
}

func (w *csvSplitWorker) startReadingLines(f util.CsvFile) error {
	fileReader, err := f.Open()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && w.skipMissingFiles {
			fmt.Fprintf(os.Stderr, "missing file, skipping: %s\n", f.Filename())
			// Open/close lines and done channels to signal we started, and we are done.
			w.lines = make(chan line)
			close(w.lines)
			w.done = make(chan error, 1)
			w.done <- nil
			close(w.done)
			return nil
		}
		return err
	}

	r := csv.NewReader(fileReader)
	r.FieldsPerRecord = -1 // don't check number of fields
	var records []string
	w.lines = make(chan line, cap(w.lines))
	w.done = make(chan error, 1)
	go func() {
		var finalErr error
		for lineNo := 1; ; lineNo++ {
			records, err = r.Read()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					finalErr = fmt.Errorf("reading %s: %w", f.Filename(), err)
				}
				break
			}
			w.lines <- line{
				fields: records,
				number: lineNo,
			}
		}
		close(w.lines)
		if err := f.Close(); err != nil {
			if finalErr != nil {
				finalErr = errors.Join(finalErr, err)
			} else {
				finalErr = err
			}
		}
		w.done <- finalErr
		close(w.done)
	}()

	return nil
}
