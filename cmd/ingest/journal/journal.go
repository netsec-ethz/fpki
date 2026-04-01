package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type Journal struct {
	JournalFile string     `json:"-"` // Exclude from JSON.
	IngestDir   string     `json:"-"` // Only used to refresh file listings.
	Cwds        []string   //`json:"Cwds"`
	Cmds        [][]string //`json:"Cmds"`

	JobConfiguration JobConfiguration //`json:"Configuration"`
	CompletedFiles   []string         // Deduplicated, sorted list.
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

func NewJobConfiguration(strategy string, fileBatch int) (JobConfiguration, error) {
	jc := JobConfiguration{
		FileBatch: fileBatch,
	}
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
		return JobConfiguration{}, fmt.Errorf("strategy value not understood by journal: %s", strategy)
	}
	return jc, nil
}

func NewJournal(journalFile string, cfg JobConfiguration, ingestDir string) (*Journal, error) {
	j := &Journal{
		JournalFile: journalFile,
		IngestDir:   ingestDir,
	}

	// Check if file exists.
	f, err := os.Open(journalFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Does not exist, create it.
		return j, j.reset(cfg, ingestDir)
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

// AddCompletedFiles adds the file names to the set of completed files.
// The function deduplicates and sorts the final set of completed files.
func (j *Journal) AddCompletedFiles(files []string) error {
	j.CompletedFiles = append(j.CompletedFiles, files...)
	if err := util.SortByBundleName(j.CompletedFiles); err != nil {
		return err
	}
	j.CompletedFiles = slices.Compact(j.CompletedFiles)

	return j.Write()
}

// PendingFiles returns the set subtraction LiveDirectoryListing - CompletedFiles.
// Since both lists are sorted and contain no repeated elements, it makes use of this fact.
func (j *Journal) PendingFiles() ([]string, error) {
	files, err := j.listFiles()
	if err != nil {
		return nil, err
	}
	completed := j.CompletedFiles

	pending := make([]string, 0, len(files))
	i, k := 0, 0

	for i < len(files) && k < len(completed) {
		switch {
		case files[i] < completed[k]:
			// This file is not in completed. Add it and move the files index.
			pending = append(pending, files[i])
			i++
		case files[i] > completed[k]:
			// This completed item is not the next possible file.
			k++
		default:
			// The file matches the completed item, move both indices.
			i++
			k++
		}
	}

	pending = append(pending, files[i:]...)
	return pending, nil
}

func (j *Journal) reset(cfg JobConfiguration, ingestDir string) error {
	// Update first to get the current CWD and os.Args.
	err := j.updateCwdOsArgs()
	if err != nil {
		return err
	}

	j.JobConfiguration = cfg
	j.IngestDir = ingestDir

	return j.Write()
}

func (j *Journal) listFiles() ([]string, error) {
	if j.IngestDir == "" {
		return nil, nil
	}

	start := time.Now()
	fmt.Println("Start listing directory...")
	defer func() {
		fmt.Printf("\nFinished listing directory in %s\n",
			time.Since(start).Round(time.Millisecond))
	}()

	gzFiles, csvFiles, err := ListCsvFiles(j.IngestDir)
	if err != nil {
		return nil, err
	}

	files := append(gzFiles, csvFiles...)
	if err := util.SortByBundleName(files); err != nil {
		return nil, err
	}
	files = slices.Compact(files)
	return files, nil
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

func (j *Journal) normalize() error {
	if err := util.SortByBundleName(j.CompletedFiles); err != nil {
		return err
	}
	j.CompletedFiles = slices.Compact(j.CompletedFiles)

	return nil
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
	if err := j.normalize(); err != nil {
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
