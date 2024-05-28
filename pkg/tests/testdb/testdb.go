package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/tools"
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
	dbName, config := configureTestDBOnly(t)

	// New context to create the DB.
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)

	// Create a new DB with that name. On exiting the function, it will be removed.
	err := createTestDB(ctx, dbName)
	require.NoError(t, err)
	cancelF() // DB was created.

	// Return the configuration and removal function.
	removeFunc := func() {
		ctx, cancelF := context.WithTimeout(context.Background(), 30*time.Second)
		err = removeTestDB(ctx, t, config)
		require.NoError(t, err)
		cancelF()
	}

	return config, removeFunc
}

func ConfigureTestDBOnly(t tests.T) *db.Configuration {
	_, conf := configureTestDBOnly(t)
	return conf
}

// ExistsDB is a quick and dirty hack to know if a db exists.
func ExistsDB(t tests.T, dbName string) bool {
	conn, err := sql.Open("mysql", "root@/sys")
	require.NoError(t, err)
	defer conn.Close()
	row := conn.QueryRow(fmt.Sprintf(
		"SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '%s'",
		dbName))
	require.NoError(t, row.Err())

	var numDBs int
	err = row.Scan(&numDBs)
	require.NoError(t, err)

	return numDBs >= 1
}

func configureTestDBOnly(t tests.T) (string, *db.Configuration) {
	dbName := t.Name()
	// Remove spurious characters.
	dbName = strings.ReplaceAll(dbName, "/", "_")

	config := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
		mysql.WithEnvironment(),
		db.WithDB(dbName))

	return dbName, config
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
	defer conn.Close()
	str := fmt.Sprintf("DROP DATABASE IF EXISTS %s", config.DBName)
	_, err := conn.DB().ExecContext(ctx, str)
	require.NoError(t, err, "error removing the database")
	return nil
}
