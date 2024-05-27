package mysql

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/netsec-ethz/fpki/pkg/db"
)

// Connect: connect to db, using the config file
func Connect(config *db.Configuration) (db.Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("nil config not allowed")
	}
	if config.Dsn == "" {
		config.Dsn = parseDSN(config)
		config.DBName = config.Values[db.KeyDBName]
		delete(config.Values, db.KeyDBName)
	}

	db, err := connect(config)
	if err != nil {
		return nil, fmt.Errorf("with DSN: %s, cannot open DB: %w", config.Dsn, err)
	}

	// Set a very small number of concurrent connections per sql.DB .
	// This avoids routines creating connections to the DB and holding vast amounts of
	// data (which impact the heap), and forcing to slow down the pipelines until the existing
	// DB connections complete their work.
	// maxConnections := 8
	maxConnections := 64 // deleteme ?
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(maxConnections)

	// Set the maximum idle connection time to a lower value than the mysql wait_timeout (8h) to
	// ensure that idle connections that are closed by the mysql DB are not reused
	connMaxIdleTime := 1 * time.Hour
	db.SetConnMaxIdleTime(connMaxIdleTime)

	// check schema
	if config.CheckSchema {
		if err := checkSchema(db); err != nil {
			return nil, fmt.Errorf("checking schema on connection: %w", err)
		}
	}
	return NewMysqlDB(db)
}

func parseDSN(config *db.Configuration) string {
	val := config.Values
	dsnString := val[keyUser]
	// If a local socket is requested, the DSN is composed of different keys.
	if path, ok := val[keyLocalSocket]; ok {
		// Form a string like "root@unix(/var/run/mysqld/mysqld.sock)/fpki"
		dsnString += fmt.Sprintf("@unix(%s)/%s",
			path, val[db.KeyDBName])
	} else {
		// Form a string like "root:password@tcp(1.1.1.1:8080)/fpki"
		if val[keyPassword] != "" {
			dsnString += ":" + val[keyPassword]
		}
		dsnString += "@tcp(" + val[keyHost]
		if val[keyPort] != "" {
			dsnString += ":" + val[keyPort]
		}
		dsnString += fmt.Sprintf(")/%s", val[db.KeyDBName])
	}

	// Remove all values that are used to establish the DSN from the remaining pairs.
	delete(val, keyUser)
	delete(val, keyPassword)
	delete(val, keyHost)
	delete(val, keyPort)
	delete(val, keyLocalSocket)

	return dsnString
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
