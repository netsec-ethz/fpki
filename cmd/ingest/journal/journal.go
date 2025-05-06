package journal

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"

	"github.com/netsec-ethz/fpki/cmd/ingest/csv"
)

type Journal struct {
	JournalFile string     `json:"-"` // Exclude from JSON.
	Cwds        []string   //`json:"Cwds"`
	Cmds        [][]string //`json:"Cmds"`

	JobConfiguration JobConfiguration //`json:"Configuration"`
	Files            []string
	CompletedFiles   []string //`json:"Completed"`
}

type JobConfiguration struct {
	IngestFiles bool
	Coalesce    bool
	UpdateSMT   bool
	FileBatch   int
}

type Job struct {
	Files []string //`json:"Files,omitempty"`
}

func NewJournal(journalFile string) (*Journal, error) {
	j := &Journal{
		JournalFile: journalFile,
	}

	// Check if file exists.
	f, err := os.Open(journalFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Does not exist, create it.
		return j, j.reset()
	case err != nil:
		return nil, fmt.Errorf("cannot use journal, file error: %w", err)
	default:
	}

	// Read the journal, if any.
	if err := j.readAndClose(f); err != nil {
		return nil, err
	}

	if err := j.updateCwdOsArgs(); err != nil {
		return nil, err
	}

	return j, j.Write()
}

func (j *Journal) AddCompletedFiles(files []string) error {
	j.CompletedFiles = append(j.CompletedFiles, files...)
	sort.Strings(j.CompletedFiles)
	return j.Write()
}

func (j *Journal) reset() error {
	// Update first to get the current CWD and os.Args.
	err := j.updateCwdOsArgs()
	if err != nil {
		return err
	}

	// Read the job configuration from command line.
	err = j.JobConfiguration.reset()
	if err != nil {
		return err
	}

	// Update the files that are present under the directory.
	gzFiles, csvFiles, err := csv.ListCsvFiles(flag.Arg(0))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	j.Files = append(gzFiles, csvFiles...)

	return j.Write()
}

func (j *Journal) updateCwdOsArgs() error {
	// Append new command line and working directories.
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	j.Cwds = append(j.Cwds, cwd)
	j.Cmds = append(j.Cmds, os.Args)

	return nil
}

func (j *Journal) Write() error {
	f, err := os.Create(j.JournalFile)
	if err != nil {
		return fmt.Errorf("cannot open journal file: %w", err)
	}
	return j.writeAndClose(f)
}

func (j *Journal) close(f *os.File) error {
	err := f.Close()
	if err != nil {
		return fmt.Errorf("cannot close journal file: %w", err)
	}
	return nil
}

func (j *Journal) write(f *os.File) error {
	buf, err := json.Marshal(*j)
	if err != nil {
		return fmt.Errorf("cannot translate journal to json: %w", err)
	}
	_, err = f.Write(buf)
	if err != nil {
		return fmt.Errorf("cannot write journal: %w", err)
	}

	return nil
}

func (j *Journal) writeAndClose(f *os.File) error {
	if err := j.write(f); err != nil {
		return err
	}
	return j.close(f)
}

func (j *Journal) read(f *os.File) error {
	buff, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("cannot read journal file: %w", err)
	}
	err = json.Unmarshal(buff, j)
	if err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	return nil
}

func (j *Journal) readAndClose(f *os.File) error {
	if err := j.read(f); err != nil {
		return err
	}
	return j.close(f)
}

func (jc *JobConfiguration) reset() error {
	fl := flag.Lookup("strategy")
	strategy := fl.Value.String()
	switch strategy {
	case "onlyingest":
		jc.IngestFiles = true
	case "":
		jc.IngestFiles = true
		fallthrough
	case "skipingest":
		jc.Coalesce = true
		fallthrough
	case "onlysmtupdate":
		jc.UpdateSMT = true
	default:
		return fmt.Errorf("strategy value not understood by journal: %s", strategy)
	}

	fl = flag.Lookup("filebatch")
	n, err := strconv.Atoi(fl.Value.String())
	if err != nil {
		return fmt.Errorf("job configuration, bad filebatch option: %s", fl.Value.String())
	}
	jc.FileBatch = n

	return nil
}
