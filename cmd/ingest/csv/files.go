package csv

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ListCsvFiles returns the .gz and .csv files sorted by name.
func ListCsvFiles(dir string) (gzFiles, csvFiles []string, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "bundled" {
			// Use all *.gz in this directory.
			d := filepath.Join(dir, e.Name())
			gzFiles, err = filepath.Glob(fmt.Sprintf("%s/*.gz", d))
			if err != nil {
				return nil, nil, err
			}
			csvFiles, err = filepath.Glob(fmt.Sprintf("%s/*.csv", dir))
			if err != nil {
				return nil, nil, err
			}
		} else {
			gzs, csvs, err := ListCsvFiles(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, nil, err
			}
			gzFiles = append(gzFiles, gzs...)
			csvFiles = append(csvFiles, csvs...)
		}
	}

	// Sort the files according to their node number.
	sortByBundleName(gzFiles)
	sortByBundleName(csvFiles)

	return
}

// sortByBundleName expects a slice of filenames of the form X-Y.{csv,gz}.
// After it returns, the slice is sorted according to uint(X).
func sortByBundleName(names []string) error {
	var errInSorting error
	sort.Slice(names, func(i, j int) bool {
		a, err := filenameToFirstSize(names[i])
		if err != nil {
			errInSorting = err
			return false
		}
		b, err := filenameToFirstSize(names[j])
		if err != nil {
			errInSorting = err
			return false
		}
		return a < b
	})
	return errInSorting
}

func filenameToFirstSize(name string) (uint64, error) {
	name = filepath.Base(name)
	tokens := strings.Split(name, "-")
	if len(tokens) != 2 {
		return 0, fmt.Errorf("filename doesn't follow convention: %s", name)
	}
	n, err := strconv.ParseUint(tokens[0], 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}
