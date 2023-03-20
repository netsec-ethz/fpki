package db

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// CreateTestDB creates a new and ready test DB with the same structure as the F-PKI one.
func CreateTestDB(ctx context.Context, dbName string) error {
	// Import the tools/create_script.sh in a bash session and run its function.
	args := []string{
		// "-c",
		// "source",
		// "./tools/create_schema.sh",
		// "&&",
		// "create_new_db",
		// dbName,
		"-c",
		fmt.Sprintf("source ./tools/create_schema.sh && create_new_db %s", dbName),
	}
	cmd := exec.Command("bash", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprint(os.Stderr, string(out))
		return err
	}

	return nil
}
