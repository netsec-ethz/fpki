package mysql

import (
	"os"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const (
	keyUser        = "MYSQL_USER"
	keyPassword    = "MYSQL_PASSWORD"
	keyHost        = "MYSQL_HOST"
	keyPort        = "MYSQL_PORT"
	keyLocalSocket = "MYSQL_LOCALSOCKET"
)

// WithEnvironment modifies the configuration with values from the environment variables.
// MYSQL_USER, MYSQL_PASSWORD, MYSQL_HOST AND MYSQL_PORT are values that a user can
// set to influence the connection. The defaults are set to yield "root@tcp(localhost)/DBNAME" as
// the DSN.
func WithEnvironment() db.ConfigurationModFunction {
	return func(c *db.Configuration) *db.Configuration {
		env := map[string]string{
			keyUser:     "root",
			keyPassword: "",
			keyHost:     "127.0.0.1",
			keyPort:     "",
		}
		for k, v := range env {
			envValue, exists := os.LookupEnv(k)
			if exists {
				v = envValue
			}
			c.Values[k] = v
		}
		return c
	}
}

// WithUser modifies the configuration to set a specific user.
func WithUser(user string) db.ConfigurationModFunction {
	return func(c *db.Configuration) *db.Configuration {
		c.Values[keyUser] = user
		return c
	}
}

// WithLocalSocket modifies the configuration so that the DSN looks like e.g.
// "root@unix(/var/run/mysqld/mysqld.sock)/fpki".
// These values can be altered by setting the socket path, the user and the DB.
func WithLocalSocket(path string) db.ConfigurationModFunction {
	return func(c *db.Configuration) *db.Configuration {
		c.Values[keyLocalSocket] = path
		return c
	}
}

func WithDefaults() db.ConfigurationModFunction {
	// Notes:
	// transaction_isolation: value corresponds to SET GLOBAL TRANSACTION ISOLATION LEVEL value
	// autocommit is true per default. We want to ensure this, as it prevents the start of a new
	//		transaction on every new connection, and we would need to commit on every statement,
	//		to prevent interlocks when inserting data from multiple workers.
	return func(c *db.Configuration) *db.Configuration {
		defaults := map[string]string{
			keyUser:                 "root",
			keyPassword:             "",
			keyHost:                 "127.0.0.1",
			keyPort:                 "",
			"interpolateParams":     "true", // 1 round trip per query
			"collation":             "binary",
			"maxAllowedPacket":      "1073741824", // 1G (cannot use "1G" as the driver uses Atoi)
			"parseTime":             "true",       // driver parses DATETIME into time.Time
			"transaction_isolation": "'READ-UNCOMMITTED'",
			"autocommit":            "true", // each statement is a transaction. Otherwise
			// we need to commit and could encounter inter locks with InnoDB.
		}
		for k, v := range defaults {
			c.Values[k] = v
		}
		return c
	}
}
