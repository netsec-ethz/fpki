package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Configuration for the db connection
type Configuration struct {
	Dsn         string
	Values      map[string]string
	CheckSchema bool // indicates if opening the connection checks the health of the schema
}

// ConfigFromEnvironment returns a valid DB connection configuration set up from environment
// variables. MYSQL_USER, MYSQL_PASSWORD, MYSQL_HOST AND MYSQL_PORT are values that a user can
// set to influence the connection. The defaults are set to yield "root@tcp(localhost)/fpki" as
// the DSN.
func ConfigFromEnvironment() *Configuration {
	env := map[string]string{"MYSQL_USER": "root", "MYSQL_PASSWORD": "", "MYSQL_HOST": "localhost", "MYSQL_PORT": ""}
	for k := range env {
		v, exists := os.LookupEnv(k)
		if exists {
			env[k] = v
		}
	}
	dsnString := env["MYSQL_USER"]
	if env["MYSQL_PASSWORD"] != "" {
		dsnString += ":" + env["MYSQL_PASSWORD"]
	}
	dsnString += "@tcp(" + env["MYSQL_HOST"]
	if env["MYSQL_PORT"] != "" {
		dsnString += ":" + env["MYSQL_PORT"]
	}
	dsnString += ")/juan"
	return &Configuration{
		Dsn: dsnString,
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
			"maxAllowedPacket":  "1073741824", // 1G (cannot use "1G" as the driver uses Atoi)
		},
	}
}

// Connect: connect to db, using the config file
func Connect(config *Configuration) (Conn, error) {
	if config == nil {
		config = ConfigFromEnvironment()
	}
	dsn, err := url.Parse(config.Dsn)
	if err != nil {
		return nil, fmt.Errorf("bad connection string: %w", err)
	}
	uri := dsn.Query()
	for k, v := range config.Values {
		uri.Add(k, v)
	}
	dsn.RawQuery = uri.Encode()
	db, err := sql.Open("mysql", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("cannot open DB: %w", err)
	}

	// value set higher could trigger issues in the system
	maxConnections := 2048
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(maxConnections)
	db.SetConnMaxLifetime(-1)              // don't close them
	db.SetConnMaxIdleTime(1 * time.Minute) // don't close them
	if _, err = db.Exec("SET GLOBAL max_connections = ?", maxConnections); err != nil {
		return nil, err
	}

	// check schema
	if config.CheckSchema {
		if err := checkSchema(db); err != nil {
			return nil, fmt.Errorf("checking schema on connection: %w", err)
		}
	}
	return NewMysqlDB(db)
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
