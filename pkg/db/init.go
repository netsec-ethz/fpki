package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

var initVars sync.Once

type Configuration struct {
	Dsn         string
	Values      map[string]string
	CheckSchema bool // indicates if opening the connection checks the health of the schema
}

func Connect(config *Configuration) (Conn, error) {
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
	db.SetMaxOpenConns(512) // TODO(juagargi) set higher for production
	db.SetMaxIdleConns(512)
	db.SetConnMaxLifetime(2 * time.Second)
	db.SetConnMaxIdleTime(1 * time.Second) // lower or equal than above
	// check schema
	if config.CheckSchema {
		if err := checkSchema(db); err != nil {
			return nil, fmt.Errorf("checking schema on connection: %w", err)
		}
	}

	return NewMysqlDB(db)
}

func Connect_old() (Conn, error) {
	dsn, err := url.Parse("root@tcp(localhost)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err) // logic error
	}
	val := dsn.Query()
	val.Add("interpolateParams", "true") // 1 round trip per query
	val.Add("collation", "binary")
	dsn.RawQuery = val.Encode()

	db, err := sql.Open("mysql", dsn.String()) // TODO(juagargi) DSN should be a parameter
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(512) // TODO(juagargi) set higher for production
	db.SetMaxIdleConns(512)
	db.SetConnMaxLifetime(-1)
	db.SetConnMaxIdleTime(-1) // lower or equal than above
	// check schema
	initVars.Do(func() {
		if err := checkSchema(db); err != nil {
			panic(err)
		}
	})

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
