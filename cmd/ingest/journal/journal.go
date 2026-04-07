package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

type Journal struct {
	mu          sync.Mutex
	closed      bool
	closeOnce   sync.Once
	JournalFile string `json:"-"` // Exclude from JSON.
	IngestDir   string `json:"-"` // Only used to refresh file listings.
	// CurrentJob keeps the active run configuration available even though the
	// persisted job history may contain entries from earlier invocations.
	CurrentJob     Job `json:"-"`
	Jobs           []Job
	CompletedFiles map[string]map[string]struct{}
}

type JobConfiguration struct {
	IngestFiles bool
	Coalesce    bool
	UpdateSMT   bool
	FileBatch   int
	// IncludePlainCSVs opts the run into also listing uncompressed `.csv`
	// bundles. When false, ingest only discovers `.gz` inputs.
	IncludePlainCSVs bool
}

type Job struct {
	Cwd              string           `json:"Cwd"`
	Cmd              []string         `json:"Cmd"`
	JobConfiguration JobConfiguration `json:"JobConfiguration"`
}

// NewJobConfiguration translates the ingest strategy flags into the journal's
// execution configuration, including whether plain `.csv` bundles should be
// considered alongside compressed `.gz` files.
func NewJobConfiguration(strategy string, fileBatch int, includePlainCSVs bool) (JobConfiguration, error) {
	jc := JobConfiguration{
		FileBatch:        fileBatch,
		IncludePlainCSVs: includePlainCSVs,
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
		if err := j.reset(cfg, ingestDir); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, fmt.Errorf("cannot use journal, file error: %w", err)
	default:
		// Read the journal, if any.
		if err := j.readAndClose(f); err != nil {
			return nil, err
		}

		if err := j.appendJob(cfg); err != nil {
			return nil, err
		}

		if err := j.Write(); err != nil {
			return nil, err
		}
	}

	j.registerShutdownHook()
	j.CurrentJob = Job{JobConfiguration: cfg}
	return j, nil
}

// AddCompletedFiles adds the file names to the set of completed files.
// The function normalizes them into ingest-dir and filename keys and inserts
// them into the nested completed-files set.
func (j *Journal) AddCompletedFiles(files []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return fmt.Errorf("cannot add completed files to closed journal")
	}

	for _, file := range files {
		ingestDirBase, fileBase, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return err
		}
		addCompletedFile(j.CompletedFiles, ingestDirBase, fileBase)
	}
	return j.writeLocked()
}

// PendingFiles returns the set subtraction LiveDirectoryListing - CompletedFiles.
// CompletedFiles is expected to already contain only normalized ingest-dir and
// filename keys, so live files are normalized on the fly before membership is checked.
func (j *Journal) PendingFiles() ([]string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return nil, fmt.Errorf("cannot read pending files from closed journal")
	}

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
	err := j.appendJob(cfg)
	if err != nil {
		return err
	}
	j.IngestDir = ingestDir

	return j.Write()
}

// listFiles refreshes the current ingest directory listing and returns the
// discovered input files in bundle order. Plain `.csv` files are only included
// when the active job configuration explicitly enables them.
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

	files := slices.Clone(gzFiles)
	// Default to the compressed bundle set and only opt into plain CSVs when
	// the current invocation requested them.
	if j.CurrentJob.JobConfiguration.IncludePlainCSVs {
		files = append(files, csvFiles...)
	}
	if err := util.SortByBundleName(files); err != nil {
		return nil, err
	}
	files = slices.Compact(files)
	return files, nil
}

// appendJob records the current working directory, process arguments, and run
// configuration as one journal history entry.
func (j *Journal) appendJob(cfg JobConfiguration) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	j.Jobs = append(j.Jobs, Job{
		Cwd:              cwd,
		Cmd:              slices.Clone(os.Args),
		JobConfiguration: cfg,
	})
	j.CurrentJob = j.Jobs[len(j.Jobs)-1]

	return nil
}

// Write persists the in-memory journal state to disk.
func (j *Journal) Write() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return fmt.Errorf("cannot write closed journal")
	}

	return j.writeLocked()
}

// Close flushes the latest journal state to disk. It is safe to call more than once.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return nil
	}
	if err := j.writeLocked(); err != nil {
		return err
	}
	j.closed = true
	return nil
}

// closeFile closes the file and wraps any filesystem error.
func closeFile(f *os.File) error {
	err := f.Close()
	if err != nil {
		return fmt.Errorf("cannot close journal file: %w", err)
	}
	return nil
}

// write encodes the journal to JSON and writes it to the provided file.
func (j *Journal) write(f *os.File) error {
	buf, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot translate journal to json: %w", err)
	}
	_, err = f.Write(buf)
	if err != nil {
		return fmt.Errorf("cannot write journal: %w", err)
	}

	return nil
}

func (j *Journal) writeLocked() error {
	dir := filepath.Dir(j.JournalFile)
	tempFile, err := os.CreateTemp(dir, filepath.Base(j.JournalFile)+".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary journal file: %w", err)
	}

	tempName := tempFile.Name()
	cleanup := func() {
		_ = os.Remove(tempName)
	}

	if err := j.write(tempFile); err != nil {
		_ = tempFile.Close()
		cleanup()
		return err
	}
	if err := tempFile.Sync(); err != nil {
		_ = tempFile.Close()
		cleanup()
		return fmt.Errorf("cannot sync journal file: %w", err)
	}
	if err := closeFile(tempFile); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tempName, j.JournalFile); err != nil {
		cleanup()
		return fmt.Errorf("cannot replace journal file: %w", err)
	}
	if err := syncDirAfterRename(dir); err != nil {
		return err
	}
	return nil
}

func (j *Journal) registerShutdownHook() {
	j.closeOnce.Do(func() {
		util.RegisterShutdownFunc(j.Close)
	})
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
	var raw Journal
	err = json.Unmarshal(buff, &raw)
	if err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	j.CompletedFiles = raw.CompletedFiles
	j.Jobs = raw.Jobs
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
	return closeFile(f)
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

// syncDirAfterRename is a NOOP (read comment inside the function).
func syncDirAfterRename(dir string) error {
	// f, err := os.Open(dir)
	// if err != nil {
	// 	return fmt.Errorf("cannot open journal directory: %w", err)
	// }
	// defer f.Close()
	// if err := f.Sync(); err != nil {
	// 	return fmt.Errorf("cannot sync journal directory: %w", err)
	// }
	// return nil

	// We trust the machine won't crash.
	// Otherwise, the code above will ensure the filesystem has written in disk the result of the
	// rename operation, thus making it more resilient to OS or machine crashes.
	return nil
}
