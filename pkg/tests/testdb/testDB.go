package testdb

import (
	"context"
	"fmt"
	"io"
	"os/exec"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/tools"
)

// CreateTestDB creates a new and ready test DB with the same structure as the F-PKI one.
func CreateTestDB(ctx context.Context, dbName string) error {
	// The create_schema script is embedded. Send it to the stdin of bash, and right after
	// send a line with the invocation of the create_new_db function.
	script := tools.CreateSchemaScript()

	// Prepare a simple bash.
	cmd := exec.Command("bash")
	// We need to write to stdin.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	// Start the command.
	err = cmd.Start()
	if err != nil {
		return err
	}

	// Write to stdin the script to import the function.
	_, err = io.WriteString(stdin, script)
	if err != nil {
		return err
	}
	// and the invocation of the function.
	_, err = io.WriteString(stdin, "create_new_db "+dbName)
	if err != nil {
		return err
	}

	// Close stdin so that bash can finish.
	err = stdin.Close()
	if err != nil {
		return err
	}
	// Get the exit code.
	err = cmd.Wait()
	if err != nil {
		return err
	}

	return nil
}

func RemoveTestDB(ctx context.Context, config *db.Configuration) error {
	conn, err := Connect(config)
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
