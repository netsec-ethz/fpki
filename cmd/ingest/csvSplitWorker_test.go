package main

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestCsvSplitWorkerReturnsFilenameOnTruncatedGzip(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "0-9.gz")

	var gzBuf bytes.Buffer
	gzw := gzip.NewWriter(&gzBuf)
	_, err := gzw.Write([]byte("a,b,c\n1,2,3\n"))
	require.NoError(t, err)
	require.NoError(t, gzw.Close())

	data := gzBuf.Bytes()
	require.Greater(t, len(data), 8)
	require.NoError(t, os.WriteFile(filename, data[:len(data)-8], 0o644))

	stats := updater.NewStatistics(time.Hour, nil)
	defer stats.Stop()

	p := &Processor{
		Manager: &updater.Manager{
			Stats: stats,
		},
	}
	w := NewCsvSplitWorker(p)

	f, err := util.LoadCsvFile(filename)
	require.NoError(t, err)

	require.NoError(t, w.startReadingLines(f))

	for {
		_, ok := <-w.lines
		if !ok {
			break
		}
	}

	err = <-w.done
	require.Error(t, err)
	require.ErrorContains(t, err, filename)
	require.ErrorContains(t, err, "unexpected EOF")
}

func TestCsvSplitWorkerSkipMissingFileWhenEnabled(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "0-9.gz")

	stats := updater.NewStatistics(time.Hour, nil)
	defer stats.Stop()

	p := &Processor{
		SkipMissing: true,
		Manager: &updater.Manager{
			Stats: stats,
		},
	}
	w := NewCsvSplitWorker(p)

	f, err := util.LoadCsvFile(filename)
	require.NoError(t, err)

	require.NoError(t, w.startReadingLines(f))

	_, ok := <-w.lines
	require.False(t, ok)
	require.NoError(t, <-w.done)
}

func TestCsvSplitWorkerMissingFileStillFailsByDefault(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "0-9.gz")

	stats := updater.NewStatistics(time.Hour, nil)
	defer stats.Stop()

	p := &Processor{
		Manager: &updater.Manager{
			Stats: stats,
		},
	}
	w := NewCsvSplitWorker(p)

	f, err := util.LoadCsvFile(filename)
	require.NoError(t, err)

	err = w.startReadingLines(f)
	require.Error(t, err)
	require.True(t, errors.Is(err, os.ErrNotExist))
}
