package mysql

import (
	"database/sql"
	"fmt"
	"net/url"

	"github.com/netsec-ethz/fpki/pkg/db"
)

// Connect: connect to db, using the config file
func Connect(config *db.Configuration) (db.Conn, error) {
	if config == nil {
		config = db.ConfigFromEnvironment()
	}

	db, err := connect(config)
	if err != nil {
		return nil, fmt.Errorf("cannot open DB: %w", err)
	}

	// Set a very small number of concurrent connections per sql.DB .
	// This avoids routines creating connections to the DB and holding vast amounts of
	// data (which impact the heap), and forcing to slow down the pipelines until the existing
	// DB connections complete their work.
	maxConnections := 8
	db.SetMaxOpenConns(maxConnections)

	// check schema
	if config.CheckSchema {
		if err := checkSchema(db); err != nil {
			return nil, fmt.Errorf("checking schema on connection: %w", err)
		}
	}
	return NewMysqlDB(db)
}

func connect(config *db.Configuration) (*sql.DB, error) {
	dsn, err := url.Parse(config.Dsn)
	if err != nil {
		return nil, fmt.Errorf("bad connection string: %w", err)
	}
	uri := dsn.Query()
	for k, v := range config.Values {
		uri.Add(k, v)
	}
	dsn.RawQuery = uri.Encode()
	return sql.Open("mysql", dsn.String())
}

func checkSchema(c *sql.DB) error {
	_, err := c.Query("SELECT COUNT(*) FROM nodes")
	if err != nil {
		return fmt.Errorf("table nodes: %w", err)
	}
	row := c.QueryRow("SHOW STATUS LIKE 'max_used_connections'")
	var varName string
	var varValue string
	if err = row.Scan(&varName, &varValue); err != nil {
		return err
	}
	fmt.Printf("***************** Init %s : %s\n", varName, varValue)
	if _, err = c.Exec("SET GLOBAL max_connections = 1024"); err != nil {
		return err
	}
	fmt.Printf("***************** Init %s : %s\n", varName, varValue)
	return nil
}
