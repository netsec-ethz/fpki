package journal

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
)

// Journal persists ingest progress so future runs can skip files whose
// certificate-index ranges are already fully covered.
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
	CompletedFiles map[string][]Interval
}

// JobConfiguration captures the ingest-mode settings that affect how one run
// should be executed and resumed.
type JobConfiguration struct {
	IngestFiles bool
	Coalesce    bool
	UpdateSMT   bool
	FileBatch   int
	// IncludePlainCSVs opts the run into also listing uncompressed `.csv`
	// bundles. When false, ingest only discovers `.gz` inputs.
	IncludePlainCSVs bool
}

// Job records one invocation of the ingest command in the journal history.
type Job struct {
	Cwd              string           `json:"Cwd"`
	Cmd              []string         `json:"Cmd"`
	JobConfiguration JobConfiguration `json:"JobConfiguration"`
}

// Interval represents an inclusive range of certificate indices.
type Interval struct {
	Start uint
	End   uint
}

var completedIntervalPattern = regexp.MustCompile(`^(\d+)-(\d+)$`)

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
		CompletedFiles: map[string][]Interval{},
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

// AddCompletedFiles adds the file names to the set of completed intervals.
// The function normalizes them into ingest-dir and interval keys and merges
// them into the nested completed-interval slices.
func (j *Journal) AddCompletedFiles(files []string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.closed {
		return fmt.Errorf("cannot add completed files to closed journal")
	}

	for _, file := range files {
		ingestDirBase, interval, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return err
		}
		addCompletedInterval(j.CompletedFiles, ingestDirBase, interval)
	}
	return j.writeLocked()
}

// PendingFiles returns the set subtraction LiveDirectoryListing - CompletedFiles.
// CompletedFiles is expected to already contain normalized ingest-dir and
// interval coverage, so live files are normalized on the fly before coverage
// is checked.
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
		ingestDirBase, interval, err := normalizeCompletedFile(file, j.IngestDir)
		if err != nil {
			return nil, err
		}
		if containsCompletedInterval(j.CompletedFiles, ingestDirBase, interval) {
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

// writeLocked atomically rewrites the journal file while the journal mutex is held.
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

// registerShutdownHook ensures the journal is flushed during global process shutdown.
func (j *Journal) registerShutdownHook() {
	j.closeOnce.Do(func() {
		util.RegisterShutdownFunc(j.Close)
	})
}

// normalize restores the CompletedFiles invariant after loading JSON:
// every entry must be stored as CompletedFiles[ingestDirBase] as a sorted,
// non-overlapping, minimal interval list.
func (j *Journal) normalize() error {
	if j.CompletedFiles == nil {
		j.CompletedFiles = map[string][]Interval{}
		return nil
	}

	for ingestDirBase, intervals := range j.CompletedFiles {
		if ingestDirBase == "" {
			return fmt.Errorf("empty ingest directory key in completed files")
		}
		if intervals == nil {
			j.CompletedFiles[ingestDirBase] = []Interval{}
			continue
		}
		normalized := make([]Interval, 0, len(intervals))
		for _, interval := range intervals {
			if interval.Start > interval.End {
				return fmt.Errorf("invalid interval %s for ingest dir %q", interval.String(), ingestDirBase)
			}
			normalized = appendInterval(normalized, interval)
		}
		j.CompletedFiles[ingestDirBase] = normalized
	}

	return nil
}

// read decodes the journal from JSON and reestablishes the in-memory invariants.
func (j *Journal) read(f *os.File) error {
	buff, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("cannot read journal file: %w", err)
	}
	var raw struct {
		Jobs           []Job           `json:"Jobs"`
		CompletedFiles json.RawMessage `json:"CompletedFiles"`
	}
	err = json.Unmarshal(buff, &raw)
	if err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	j.Jobs = raw.Jobs
	completedFiles, err := decodeCompletedFiles(raw.CompletedFiles)
	if err != nil {
		return fmt.Errorf("journal file wrong format: %w", err)
	}
	j.CompletedFiles = completedFiles
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

// decodeCompletedFiles accepts both the current interval-array encoding and the
// legacy filename-set encoding, returning normalized interval coverage.
func decodeCompletedFiles(raw json.RawMessage) (map[string][]Interval, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string][]Interval{}, nil
	}

	var newFormat map[string][]string
	if err := json.Unmarshal(raw, &newFormat); err == nil {
		completed := make(map[string][]Interval, len(newFormat))
		for ingestDirBase, encodedIntervals := range newFormat {
			intervals := make([]Interval, 0, len(encodedIntervals))
			for _, encoded := range encodedIntervals {
				interval, err := parseIntervalString(encoded)
				if err != nil {
					return nil, err
				}
				intervals = append(intervals, interval)
			}
			completed[ingestDirBase] = intervals
		}
		return completed, nil
	}

	var legacyFormat map[string]map[string]struct{}
	if err := json.Unmarshal(raw, &legacyFormat); err == nil {
		completed := make(map[string][]Interval, len(legacyFormat))
		for ingestDirBase, files := range legacyFormat {
			for fileBase := range files {
				interval, err := parseFileInterval(fileBase)
				if err != nil {
					return nil, err
				}
				addCompletedInterval(completed, ingestDirBase, interval)
			}
		}
		return completed, nil
	}

	return nil, fmt.Errorf("unsupported completed files encoding")
}

// journalOnDisk is the persisted JSON shape for journal state.
type journalOnDisk struct {
	Jobs           []Job               `json:"Jobs"`
	CompletedFiles map[string][]string `json:"CompletedFiles"`
}

// MarshalJSON serializes the in-memory interval representation into the
// human-readable on-disk string-array format.
func (j *Journal) MarshalJSON() ([]byte, error) {
	onDisk := journalOnDisk{
		Jobs:           j.Jobs,
		CompletedFiles: make(map[string][]string, len(j.CompletedFiles)),
	}
	for ingestDirBase, intervals := range j.CompletedFiles {
		encoded := make([]string, len(intervals))
		for i, interval := range intervals {
			encoded[i] = interval.String()
		}
		onDisk.CompletedFiles[ingestDirBase] = encoded
	}
	return json.Marshal(onDisk)
}

// addCompletedInterval inserts a completed interval into the nested set,
// creating the ingest-dir bucket when needed.
func addCompletedInterval(completed map[string][]Interval, ingestDirBase string, interval Interval) {
	intervals, ok := completed[ingestDirBase]
	if !ok {
		intervals = []Interval{}
	}
	completed[ingestDirBase] = appendInterval(intervals, interval)
}

// appendInterval inserts one interval into an existing sorted interval list,
// merging overlaps and adjacencies to preserve a minimal canonical form.
func appendInterval(intervals []Interval, interval Interval) []Interval {
	// Find the insertion point by interval start. Because the slice is kept
	// sorted, only the interval immediately before the insertion point and any
	// intervals starting at or after it can possibly merge with the new range.
	idx, _ := slices.BinarySearchFunc(intervals, interval, func(existing, target Interval) int {
		switch {
		case existing.Start < target.Start:
			return -1
		case existing.Start > target.Start:
			return 1
		default:
			return 0
		}
	})

	// First absorb a predecessor if it overlaps with or directly touches the
	// new interval. This may shift the insertion point left by one slot.
	if idx > 0 && canMerge(intervals[idx-1], interval) {
		idx--
		interval = mergeIntervals(intervals[idx], interval)
		intervals = append(intervals[:idx], intervals[idx+1:]...)
	}
	// Then keep consuming following intervals for as long as the merged range
	// still overlaps or touches them, yielding one minimal interval in the end.
	for idx < len(intervals) && canMerge(interval, intervals[idx]) {
		interval = mergeIntervals(interval, intervals[idx])
		intervals = append(intervals[:idx], intervals[idx+1:]...)
	}

	// Reinsert the final merged interval at the computed position while
	// preserving sort order.
	intervals = append(intervals, Interval{})
	copy(intervals[idx+1:], intervals[idx:])
	intervals[idx] = interval
	return intervals
}

// canMerge reports whether two inclusive intervals overlap or touch.
func canMerge(a, b Interval) bool {
	return a.Start <= b.End+1 && b.Start <= a.End+1
}

// mergeIntervals returns the smallest interval covering both inputs.
func mergeIntervals(a, b Interval) Interval {
	return Interval{
		Start: min(a.Start, b.Start),
		End:   max(a.End, b.End),
	}
}

// containsCompletedInterval reports whether the nested completed interval set
// fully covers the given ingest-dir and interval pair.
func containsCompletedInterval(completed map[string][]Interval, ingestDirBase string, interval Interval) bool {
	intervals, ok := completed[ingestDirBase]
	if !ok {
		return false
	}
	idx, found := slices.BinarySearchFunc(intervals, interval, func(existing, target Interval) int {
		switch {
		case existing.Start < target.Start:
			return -1
		case existing.Start > target.Start:
			return 1
		default:
			return 0
		}
	})
	if found {
		return intervals[idx].End >= interval.End
	}
	if idx == 0 {
		return false
	}
	candidate := intervals[idx-1]
	return candidate.Start <= interval.Start && candidate.End >= interval.End
}

// normalizeCompletedFile converts a current-run file path into the canonical
// ingest-dir and interval pair.
func normalizeCompletedFile(file string, ingestDir string) (string, Interval, error) {
	if ingestDir == "" {
		return "", Interval{}, fmt.Errorf("cannot normalize completed file %q without ingest directory", file)
	}
	interval, err := parseFileInterval(file)
	if err != nil {
		return "", Interval{}, err
	}
	return filepath.Base(filepath.Clean(ingestDir)), interval, nil
}

// parseFileInterval extracts an inclusive interval from a bundle filename such
// as `A-B.gz` or `A-B.csv`.
func parseFileInterval(file string) (Interval, error) {
	filename := filepath.Base(file)
	if ext := filepath.Ext(filename); ext == ".gz" || ext == ".csv" {
		filename = filename[:len(filename)-len(ext)]
	}
	interval, err := parseIntervalString(filename)
	if err != nil {
		return Interval{}, fmt.Errorf("cannot parse completed file %q: %w", file, err)
	}
	return interval, nil
}

// parseIntervalString parses the persisted `A-B` interval encoding.
func parseIntervalString(value string) (Interval, error) {
	groups := completedIntervalPattern.FindStringSubmatch(value)
	if len(groups) != 3 {
		return Interval{}, fmt.Errorf("unexpected interval %q", value)
	}
	start, err := strconv.ParseUint(groups[1], 10, 64)
	if err != nil {
		return Interval{}, fmt.Errorf("unexpected interval %q", value)
	}
	end, err := strconv.ParseUint(groups[2], 10, 64)
	if err != nil {
		return Interval{}, fmt.Errorf("unexpected interval %q", value)
	}
	interval := Interval{Start: uint(start), End: uint(end)}
	if interval.Start > interval.End {
		return Interval{}, fmt.Errorf("unexpected interval %q", value)
	}
	return interval, nil
}

// String formats the interval using the persisted inclusive `A-B` form.
func (i Interval) String() string {
	return fmt.Sprintf("%d-%d", i.Start, i.End)
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
