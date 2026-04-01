package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateDiagnosticsBundleWritesExpectedFiles(t *testing.T) {
	root := t.TempDir()
	origRoot := diagnosticsRootDir
	origNow := diagnosticsNow
	origProcessStart := diagnosticsProcessStart
	diagnosticsRootDir = root
	diagnosticsNow = func() time.Time { return time.Date(2026, 3, 31, 9, 12, 13, 456000000, time.UTC) }
	diagnosticsProcessStart = time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		diagnosticsRootDir = origRoot
		diagnosticsNow = origNow
		diagnosticsProcessStart = origProcessStart
	})

	cfg := RunConfig{
		Directory:       "/input",
		Strategy:        "onlyingest",
		JournalFile:     "/tmp/journal.json",
		FileBatch:       200,
		MultiInsertSize: 1000,
		NumFiles:        16,
		NumParsers:      8,
		NumChainToCerts: 4,
		NumDBWriters:    2,
	}

	var stderr bytes.Buffer
	dir, err := createDiagnosticsBundle(cfg, syscall.SIGUSR1, &stderr)
	require.NoError(t, err)
	require.DirExists(t, dir)
	require.Equal(t, root, filepath.Dir(dir))
	require.Equal(t, "fpki-diagnostics-20260331-091213.456", filepath.Base(dir))

	for _, name := range []string{
		"heap.pprof",
		"heap-after-gc.pprof",
		"allocs.pprof",
		"goroutines.txt",
		"memstats.txt",
		"meta.txt",
	} {
		require.FileExists(t, filepath.Join(dir, name))
	}
}

func TestCreateDiagnosticsBundleWritesMetadata(t *testing.T) {
	root := t.TempDir()
	origRoot := diagnosticsRootDir
	origNow := diagnosticsNow
	origProcessStart := diagnosticsProcessStart
	diagnosticsRootDir = root
	diagnosticsNow = func() time.Time { return time.Date(2026, 3, 31, 9, 12, 13, 456000000, time.UTC) }
	diagnosticsProcessStart = time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		diagnosticsRootDir = origRoot
		diagnosticsNow = origNow
		diagnosticsProcessStart = origProcessStart
	})

	cfg := RunConfig{
		Directory:       "/input",
		Strategy:        "onlyingest",
		JournalFile:     "/tmp/journal.json",
		FileBatch:       200,
		MultiInsertSize: 1000,
		NumFiles:        16,
		NumParsers:      8,
		NumChainToCerts: 4,
		NumDBWriters:    2,
	}

	var stderr bytes.Buffer
	dir, err := createDiagnosticsBundle(cfg, syscall.SIGTERM, &stderr)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "meta.txt"))
	require.NoError(t, err)
	text := string(data)
	require.Contains(t, text, "timestamp=2026-03-31T09:12:13.456Z")
	require.Contains(t, text, "process_start=2026-03-31T09:00:00Z")
	require.Contains(t, text, "uptime=12m13.456s")
	require.Contains(t, text, "uptime_seconds=733.456000")
	require.Contains(t, text, "signal=terminated")
	require.Contains(t, text, "strategy=onlyingest")
	require.Contains(t, text, "filebatch=200")
	require.Contains(t, text, "multiinsert=1000")
	require.Contains(t, text, "numfiles=16")
	require.Contains(t, text, "numparsers=8")
	require.Contains(t, text, "numdechainers=4")
	require.Contains(t, text, "numdbworkers=2")
	require.Contains(t, text, "directory=/input")
	require.Contains(t, text, "journal=/tmp/journal.json")
	require.Contains(t, text, `args=[`)
}

func TestCreateDiagnosticsBundleCreatesDifferentDirectories(t *testing.T) {
	root := t.TempDir()
	origRoot := diagnosticsRootDir
	origNow := diagnosticsNow
	origProcessStart := diagnosticsProcessStart
	diagnosticsRootDir = root
	times := []time.Time{
		time.Date(2026, 3, 31, 9, 12, 13, 456000000, time.UTC),
		time.Date(2026, 3, 31, 9, 12, 13, 456000000, time.UTC),
		time.Date(2026, 3, 31, 9, 12, 13, 457000000, time.UTC),
		time.Date(2026, 3, 31, 9, 12, 13, 457000000, time.UTC),
	}
	diagnosticsProcessStart = time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC)
	diagnosticsNow = func() time.Time {
		tm := times[0]
		times = times[1:]
		return tm
	}
	t.Cleanup(func() {
		diagnosticsRootDir = origRoot
		diagnosticsNow = origNow
		diagnosticsProcessStart = origProcessStart
	})

	var stderr bytes.Buffer
	dir1, err := createDiagnosticsBundle(RunConfig{}, syscall.SIGUSR1, &stderr)
	require.NoError(t, err)
	dir2, err := createDiagnosticsBundle(RunConfig{}, syscall.SIGUSR1, &stderr)
	require.NoError(t, err)

	require.NotEqual(t, dir1, dir2)

	entries, err := os.ReadDir(root)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestCreateDiagnosticsBundleToleratesPartialFailures(t *testing.T) {
	root := t.TempDir()
	bundleDir := filepath.Join(root, "bundle")
	require.NoError(t, os.Mkdir(bundleDir, 0o755))

	writeOK := func(path string) error {
		return os.WriteFile(path, []byte("ok"), 0o644)
	}

	writer := diagnosticsWriter{
		createDir:        func() (string, error) { return bundleDir, nil },
		writeHeap:        writeOK,
		writeHeapAfterGC: writeOK,
		writeAllocs: func(string) error {
			return fmt.Errorf("allocs unavailable")
		},
		writeGoroutines: writeOK,
		writeMemStats:   writeOK,
		writeMeta: func(path string, _ diagnosticsMeta) error {
			return os.WriteFile(path, []byte("meta"), 0o644)
		},
	}

	var stderr bytes.Buffer
	dir, err := createDiagnosticsBundleWithWriter(RunConfig{}, syscall.SIGUSR1, &stderr, writer)
	require.Error(t, err)
	require.Equal(t, bundleDir, dir)

	require.FileExists(t, filepath.Join(dir, "heap.pprof"))
	require.NoFileExists(t, filepath.Join(dir, "allocs.pprof"))
	require.FileExists(t, filepath.Join(dir, "goroutines.txt"))
	require.FileExists(t, filepath.Join(dir, "memstats.txt"))
	require.FileExists(t, filepath.Join(dir, "heap-after-gc.pprof"))
	require.FileExists(t, filepath.Join(dir, "meta.txt"))
	require.Contains(t, stderr.String(), "writing allocs.pprof")
}

func TestCreateDiagnosticsDirUsesTimestampedNames(t *testing.T) {
	root := t.TempDir()
	origRoot := diagnosticsRootDir
	origNow := diagnosticsNow
	origProcessStart := diagnosticsProcessStart
	diagnosticsRootDir = root
	diagnosticsNow = func() time.Time { return time.Date(2026, 3, 31, 9, 12, 13, 456000000, time.UTC) }
	diagnosticsProcessStart = time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC)
	t.Cleanup(func() {
		diagnosticsRootDir = origRoot
		diagnosticsNow = origNow
		diagnosticsProcessStart = origProcessStart
	})

	dir, err := createDiagnosticsDir()
	require.NoError(t, err)

	base := filepath.Base(dir)
	require.Equal(t, "fpki-diagnostics-20260331-091213.456", base)
	require.True(t, strings.HasPrefix(base, "fpki-diagnostics-"))
}
