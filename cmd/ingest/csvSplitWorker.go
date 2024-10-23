package main

import (
	"encoding/csv"
	"fmt"

	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
	"go.opentelemetry.io/otel/attribute"
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

	channelsCache []int // reuse storage
}

func NewCsvSplitWorker(p *Processor) *csvSplitWorker {
	w := &csvSplitWorker{
		channelsCache: make([]int, 0),
	}
	w.Stage = pip.NewStage[util.CsvFile, line](
		"csv_split",
		pip.WithMultiOutputChannels[util.CsvFile, line](p.NumWorkers),
		pip.WithProcessFunction(
			func(in util.CsvFile) ([]line, []int, error) {
				ctx, span := tr.T().Start(w.Stage.Ctx, "csv_split-new-file")
				w.Stage.Ctx = ctx
				defer span.End()
				span.SetAttributes(
					attribute.String("file-name", in.Filename()),
				)

				p.stats.TotalFilesRead.Add(1)
				// Split the file into multiple lines.
				lines, err := w.splitFile(in)
				if err != nil {
					return nil, nil, err
				}
				span.SetAttributes(
					attribute.Int("lines", len(lines)),
				)

				// Prepare the staggered fan-out list of output channels.
				w.channelsCache = w.channelsCache[:0]
				for i := 0; i < len(lines); i++ {
					w.channelsCache = append(w.channelsCache, i%p.NumWorkers)
				}

				return lines, w.channelsCache, nil
			},
		),
	)
	return w
}

func (w *csvSplitWorker) splitFile(f util.CsvFile) ([]line, error) {
	fileReader, err := f.Open()
	if err != nil {
		return nil, err
	}

	r := csv.NewReader(fileReader)
	r.FieldsPerRecord = -1 // don't check number of fields

	// TODO: try to reuse storage by calling r.ReuseRecord and copying.
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	// Close the csv file.
	if err := f.Close(); err != nil {
		return nil, err
	}

	// Convert records to lines (cast each line).
	lines := make([]line, len(records))
	for i, l := range records {
		lines[i] = line{
			fields: l,
			number: i + 1,
		}
	}

	return lines, nil
}
