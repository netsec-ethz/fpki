package tests

import (
	"flag"
)

// Update registers the '-update' flag for the test.
//
// This flag should be checked by golden file tests to see whether the golden
// files should be updated or not. The golden files should be deterministic.
// Use UpdateNonDeterminsticGoldenFiles instead, if they are not deterministic.
//
// To update all golden files, run the following command:
//
//	go test ./... -update
//
// To update a specific package, run the following command:
//
//	go test ./path/to/package -update
//
// The flag should be registered as a package global variable:
//
//	var update = tests.UpdateGoldenFiles()
func UpdateGoldenFiles() *bool {
	return flag.Bool("update", false, "set to regenerate the golden files")
}
