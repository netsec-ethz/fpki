package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/fpki/cmd/ingest/fastcsv"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type line struct {
	certField       []byte
	chainField      []byte
	expirationField []byte
	number          int
}

func (l line) String() string {
	return fmt.Sprintf("line %06d", l.number)
}

// csvSplitWorker is a processing stage that takes a CsvFile and outputs all its lines.
// The distribution is done in a staggered fan-out way to the next stages, so that each next
// stage i processes lines i, i+W, i+2W, etc (W being the number or next stages).
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

	r := bufio.NewReader(fileReader)
	w.lines = make(chan line, cap(w.lines))
	w.done = make(chan error, 1)
	go func() {
		var finalErr error
		for lineNo := 1; ; lineNo++ {
			// Read one physical row at a time so we can keep the fast-path parser byte-oriented
			// and avoid materializing a full []string record for the common case.
			rawLine, readErr := r.ReadBytes('\n')
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				finalErr = fmt.Errorf("reading %s: %w", f.Filename(), readErr)
				break
			}
			if len(rawLine) > 0 {
				parsed, parseErr := fastcsv.ParseLine(rawLine, f.Filename(), lineNo)
				if parseErr != nil {
					// If row parsing fails, continue draining the reader first. This preserves
					// underlying stream errors such as truncated gzip data instead of masking them
					// behind a row-shape error from the fast parser.
					drainErr := drainReader(r)
					if errors.Is(readErr, io.EOF) {
						finalErr = errors.Join(
							fmt.Errorf("reading %s: %w", f.Filename(), io.ErrUnexpectedEOF),
							parseErr,
						)
					} else if drainErr != nil {
						finalErr = errors.Join(
							fmt.Errorf("reading %s: %w", f.Filename(), drainErr),
							parseErr,
						)
					} else {
						finalErr = parseErr
					}
					break
				}
				// Forward only the compact, ingest-relevant fields to the next stage.
				w.lines <- line{
					certField:       parsed.CertField,
					chainField:      parsed.ChainField,
					expirationField: parsed.ExpirationField,
					number:          parsed.Number,
				}
			}
			// EOF after a successfully parsed final row is the normal termination path.
			if errors.Is(readErr, io.EOF) {
				break
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

func drainReader(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
