package journal

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strconv"

	"github.com/netsec-ethz/fpki/pkg/util"
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
	if err := util.SortByBundleName(j.CompletedFiles); err != nil {
		return err
	}
	j.CompletedFiles = slices.Compact(j.CompletedFiles)

	// deleteme TODO decide if commenting out the printf below.
	// fmt.Printf("COMPLETED FILES NOW: %s\n", strings.Join(j.CompletedFiles, ", "))
	fmt.Printf("\nCOMPLETED FILES NOW: %d\n", len(j.CompletedFiles))

	return j.Write()
}

// PendingFiles returns the set substraction Files - CompletedFiles.
// Since both Files and CompletedFiles are sorted and contain no repeated elements,
// it makes use of this fact.
func (j *Journal) PendingFiles() []string {
	files := slices.Clone(j.Files)
	// Remove those completed ones.
	var i int
	for _, f := range j.CompletedFiles {
		// The index "i" indicates the last occurence found, i.e. the min index where a element
		// in Files could be equal to any remaining elements in CompletedFiles.
		idx := sort.SearchStrings(files[i:], f)
		if idx == len(files) {
			continue
		}
		// One is found. We don't need to look at previous elements in files, since they can
		// never be equal (or greater) than the next CompletedFiles elements.
		// Remove the found item, drag the next
		i = idx

		// Remove from the return value.
		files = slices.Delete(files, idx, idx+1)
	}

	return files
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

	// Update with all the GZ and CSV files present under the directory of the argument.
	gzFiles, csvFiles, err := ListCsvFiles(flag.Arg(0))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	j.Files = append(gzFiles, csvFiles...)
	if err := util.SortByBundleName(j.Files); err != nil {
		return err
	}
	j.Files = slices.Compact(j.Files)

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
	buf, err := json.MarshalIndent(*j, "", "  ")
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
