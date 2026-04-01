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
// The function normalizes them into journal keys and keeps the final set
// deduplicated and sorted.
func (j *Journal) AddCompletedFiles(files []string) error {
	normalized, err := normalizeCompletedFiles(files, j.IngestDir)
	if err != nil {
		return err
	}
	j.CompletedFiles = append(j.CompletedFiles, normalized...)
	if err := sortCompactCompletedFiles(&j.CompletedFiles); err != nil {
		return err
	}

	return j.Write()
}

// PendingFiles returns the set subtraction LiveDirectoryListing - CompletedFiles.
// CompletedFiles is expected to already contain only normalized journal keys,
// so live files are normalized on the fly before membership is checked.
func (j *Journal) PendingFiles() ([]string, error) {
	files, err := j.listFiles()
	if err != nil {
		return nil, err
	}
	completed := make(map[string]struct{}, len(j.CompletedFiles))
	for _, key := range j.CompletedFiles {
		completed[key] = struct{}{}
	}

	pending := make([]string, 0, len(files))
	for _, file := range files {
		key, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return nil, err
		}
		if _, ok := completed[key]; ok {
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

// writeAndClose writes the journal contents and then closes the destination file.
func (j *Journal) writeAndClose(f *os.File) error {
	if err := j.write(f); err != nil {
		return err
	}
	return j.close(f)
}

// normalize restores the CompletedFiles invariant after loading JSON:
// every entry must be stored as "basename(ingestDir)/basename(file)".
func (j *Journal) normalize() error {
	normalized, err := normalizeCompletedFiles(j.CompletedFiles, "")
	if err != nil {
		return err
	}
	j.CompletedFiles = normalized
	return nil
}

// read decodes the journal from JSON and reestablishes the in-memory invariants.
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

// readAndClose reads the journal from disk and then closes the file handle.
func (j *Journal) readAndClose(f *os.File) error {
	if err := j.read(f); err != nil {
		return err
	}
	return j.close(f)
}

// sortCompactCompletedFiles keeps a slice of journal keys sorted by bundle name
// and removes duplicates.
func sortCompactCompletedFiles(files *[]string) error {
	if err := util.SortByBundleName(*files); err != nil {
		return err
	}
	*files = slices.Compact(*files)
	return nil
}

// normalizeCompletedFiles converts a batch of file identifiers into normalized
// journal keys and returns them sorted and deduplicated.
func normalizeCompletedFiles(files []string, ingestDir string) ([]string, error) {
	normalized := make([]string, len(files))
	for i, file := range files {
		key, err := normalizeCompletedFile(file, ingestDir)
		if err != nil {
			return nil, err
		}
		normalized[i] = key
	}
	if err := sortCompactCompletedFiles(&normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

// normalizeCompletedFile converts either a current-run file path or a stored
// journal entry into the canonical "ingest-dir-basename/file-basename" key.
func normalizeCompletedFile(file string, ingestDir string) (string, error) {
	if ingestDir != "" {
		return filepath.Join(filepath.Base(filepath.Clean(ingestDir)), filepath.Base(file)), nil
	}

	file = filepath.Clean(file)
	dir := filepath.Dir(file)
	if dir == "." {
		return "", fmt.Errorf("cannot normalize completed file %q", file)
	}

	// Already normalized: "ingest-dir-basename/filename".
	parent := filepath.Dir(dir)
	if parent == "." {
		return filepath.Join(filepath.Base(dir), filepath.Base(file)), nil
	}

	// Legacy entries store full paths. For files in "bundled/", the ingest dir
	// is the parent of "bundled"; otherwise it is the direct parent directory.
	ingestDirBase := filepath.Base(dir)
	if ingestDirBase == "bundled" {
		ingestDirBase = filepath.Base(parent)
	}
	if ingestDirBase == "." || ingestDirBase == string(filepath.Separator) || ingestDirBase == "" {
		return "", fmt.Errorf("cannot normalize completed file %q", file)
	}
	return filepath.Join(ingestDirBase, filepath.Base(file)), nil
}
