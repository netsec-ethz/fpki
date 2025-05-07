package journal

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/netsec-ethz/fpki/pkg/util"
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
	util.SortByBundleName(gzFiles)
	util.SortByBundleName(csvFiles)

	return
}
