package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	CompletedFiles   map[string]map[string]struct{}
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

type journalJSON struct {
	Cwds             []string                       `json:"Cwds"`
	Cmds             [][]string                     `json:"Cmds"`
	JobConfiguration JobConfiguration               `json:"JobConfiguration"`
	CompletedFiles   map[string]map[string]struct{} `json:"CompletedFiles"`
}

// NewJobConfiguration translates the ingest strategy flags into the journal's
// execution configuration.
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

// NewJournal loads or creates the journal file and normalizes any stored
// completed-file entries into the journal key format.
func NewJournal(journalFile string, cfg JobConfiguration, ingestDir string) (*Journal, error) {
	j := &Journal{
		JournalFile:    journalFile,
		IngestDir:      ingestDir,
		CompletedFiles: map[string]map[string]struct{}{},
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
// The function normalizes them into ingest-dir and filename keys and inserts
// them into the nested completed-files set.
func (j *Journal) AddCompletedFiles(files []string) error {
	for _, file := range files {
		ingestDirBase, fileBase, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return err
		}
		addCompletedFile(j.CompletedFiles, ingestDirBase, fileBase)
	}

	return j.Write()
}

// PendingFiles returns the set subtraction LiveDirectoryListing - CompletedFiles.
// CompletedFiles is expected to already contain only normalized ingest-dir and
// filename keys, so live files are normalized on the fly before membership is checked.
func (j *Journal) PendingFiles() ([]string, error) {
	files, err := j.listFiles()
	if err != nil {
		return nil, err
	}

	pending := make([]string, 0, len(files))
	for _, file := range files {
		ingestDirBase, fileBase, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return nil, err
		}
		if containsCompletedFile(j.CompletedFiles, ingestDirBase, fileBase) {
			continue
		}
		pending = append(pending, file)
	}
	return pending, nil
}

// reset initializes a new journal instance with the current run configuration.
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

// listFiles refreshes the current ingest directory listing and returns the
// discovered CSV/GZ files in bundle order.
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

// updateCwdOsArgs appends the current working directory and process arguments
// to the journal history.
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

// Write persists the in-memory journal state to disk.
func (j *Journal) Write() error {
	f, err := os.Create(j.JournalFile)
	if err != nil {
		return fmt.Errorf("cannot open journal file: %w", err)
	}
	return j.writeAndClose(f)
}

// close closes the journal file and wraps any filesystem error.
func (j *Journal) close(f *os.File) error {
	err := f.Close()
	if err != nil {
		return fmt.Errorf("cannot close journal file: %w", err)
	}
	return nil
}

// write encodes the journal to JSON and writes it to the provided file.
func (j *Journal) write(f *os.File) error {
	buf, err := json.MarshalIndent(journalJSON{
		Cwds:             j.Cwds,
		Cmds:             j.Cmds,
		JobConfiguration: j.JobConfiguration,
		CompletedFiles:   j.CompletedFiles,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot translate journal to json: %w", err)
	}
	_, err = f.Write(buf)
	if err != nil {
		return fmt.Errorf("cannot write journal: %w", err)
	}

	return nil
}

// writeAndClose writes the journal contents and then closes the destination file.
func (j *Journal) writeAndClose(f *os.File) error {
	if err := j.write(f); err != nil {
		return err
	}
	return j.close(f)
}

// normalize restores the CompletedFiles invariant after loading JSON:
// every entry must be stored as CompletedFiles[ingestDirBase][fileBase].
func (j *Journal) normalize() error {
	if j.CompletedFiles == nil {
		j.CompletedFiles = map[string]map[string]struct{}{}
		return nil
	}

	for ingestDirBase, files := range j.CompletedFiles {
		if ingestDirBase == "" {
			return fmt.Errorf("empty ingest directory key in completed files")
		}
		if files == nil {
			j.CompletedFiles[ingestDirBase] = map[string]struct{}{}
			continue
		}
		for fileBase := range files {
			if fileBase == "" {
				return fmt.Errorf("empty file key in completed files for ingest dir %q", ingestDirBase)
			}
		}
	}

	return nil
}

// read decodes the journal from JSON and reestablishes the in-memory invariants.
func (j *Journal) read(f *os.File) error {
	buff, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("cannot read journal file: %w", err)
	}
	var raw journalJSON
	err = json.Unmarshal(buff, &raw)
	if err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	j.Cwds = raw.Cwds
	j.Cmds = raw.Cmds
	j.JobConfiguration = raw.JobConfiguration
	j.CompletedFiles = raw.CompletedFiles
	if err := j.normalize(); err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	return nil
}

// readAndClose reads the journal from disk and then closes the file handle.
func (j *Journal) readAndClose(f *os.File) error {
	if err := j.read(f); err != nil {
		return err
	}
	return j.close(f)
}

// addCompletedFile inserts a completed file into the nested set, creating the
// ingest-dir bucket when needed.
func addCompletedFile(completed map[string]map[string]struct{}, ingestDirBase, fileBase string) {
	files, ok := completed[ingestDirBase]
	if !ok {
		files = map[string]struct{}{}
		completed[ingestDirBase] = files
	}
	files[fileBase] = struct{}{}
}

// containsCompletedFile reports whether the nested completed-files set already
// contains the given ingest-dir and filename pair.
func containsCompletedFile(completed map[string]map[string]struct{}, ingestDirBase, fileBase string) bool {
	files, ok := completed[ingestDirBase]
	if !ok {
		return false
	}
	_, ok = files[fileBase]
	return ok
}

// normalizeCompletedFile converts a current-run file path into the canonical
// ingest-dir and filename pair.
func normalizeCompletedFile(file string, ingestDir string) (string, string, error) {
	if ingestDir == "" {
		return "", "", fmt.Errorf("cannot normalize completed file %q without ingest directory", file)
	}
	return filepath.Base(filepath.Clean(ingestDir)), filepath.Base(file), nil
}
