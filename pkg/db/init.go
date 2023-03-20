package db

import (
	"os"

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
	env := map[string]string{
		"MYSQL_USER":     "root",
		"MYSQL_PASSWORD": "",
		"MYSQL_HOST":     "127.0.0.1",
		"MYSQL_PORT":     "",
	}
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
	dsnString += ")/fpki"
	// fmt.Printf("FPKI | DB INIT | using dsn: %s\n", dsnString)
	return &Configuration{
		Dsn: dsnString,
		Values: map[string]string{
			"interpolateParams": "true", // 1 round trip per query
			"collation":         "binary",
			"maxAllowedPacket":  "1073741824", // 1G (cannot use "1G" as the driver uses Atoi)
		},
	}
}
