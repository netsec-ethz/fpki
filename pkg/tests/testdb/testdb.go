package testdb

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/tools"
	"github.com/stretchr/testify/require"
)

type Conn db.Conn

func Connect(t tests.T, config *db.Configuration) db.Conn {
	conn, err := mysql.Connect(config)
	require.NoError(t, err)
	return conn
}

// ConfigureTestDB creates a new configuration and database with the name of the test, and
// returns the configuration and the DB removal function that should be called with defer.
func ConfigureTestDB(t tests.T) (*db.Configuration, func()) {
	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), mysql.WithEnvironment(), db.WithDB(dbName))

	// New context to create the DB.
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)

	// Create a new DB with that name. On exiting the function, it will be removed.
	err := createTestDB(ctx, dbName)
	require.NoError(t, err)
	cancelF() // DB was created.

	// Return the configuration and removal function.
	removeFunc := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
		err = removeTestDB(ctx, t, config)
		require.NoError(t, err)
		cancelF()
	}

	return config, removeFunc
}

// createTestDB creates a new and ready test DB with the same structure as the F-PKI one.
func createTestDB(ctx context.Context, dbName string) error {
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

	// Collect the output in case of error.
	var output string
	{
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		go func() {
			multi := io.MultiReader(stderr, stdout)
			b, err := io.ReadAll(multi)
			output = string(b)
			if err != nil {
				output += "\nError reading stderr and stdout"
			}
		}()
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
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("exit error: %w. STDERR+STDOUT: %s", exitErr, output)
		}
		return err
	}

	return nil
}

// removeTestDB removes a test DB that was created with CreateTestDB.
func removeTestDB(ctx context.Context, t tests.T, config *db.Configuration) error {
	conn := Connect(t, config)
	str := fmt.Sprintf("DROP DATABASE IF EXISTS %s", config.DBName)
	_, err := conn.DB().ExecContext(ctx, str)
	require.NoError(t, err, "error removing the database")
	return nil
}
