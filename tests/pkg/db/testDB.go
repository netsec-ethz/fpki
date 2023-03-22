package db

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
)

// CreateTestDB creates a new and ready test DB with the same structure as the F-PKI one.
func CreateTestDB(ctx context.Context, dbName string) error {
	// Import the tools/create_script.sh in a bash session and run its function.
	args := []string{
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

func RemoveTestDB(ctx context.Context, config db.Configuration) error {
	conn, err := Connect(&config)
	if err != nil {
		return fmt.Errorf("connecting to test DB: %w", err)
	}
	str := fmt.Sprintf("DROP DATABASE IF EXISTS %s", config.DBName)
	_, err = conn.DB().ExecContext(ctx, str)
	if err != nil {
		return fmt.Errorf("removing the database: %w", err)
	}
	return nil
}

func Connect(config *db.Configuration) (db.Conn, error) {
	return mysql.Connect(config)
}
