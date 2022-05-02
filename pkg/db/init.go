package db

import (
	"database/sql"
	"fmt"
	"net/url"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func Connect() (DB, error) {
	fmt.Println("connect")
	dsn, err := url.Parse("root@tcp(localhost)/fpki")
	if err != nil {
		panic(err) // logic error
	}
	val := dsn.Query()
	val.Add("interpolateParams", "true") // 1 round trip per query
	dsn.RawQuery = val.Encode()
	fmt.Printf("connecting with %s\n", dsn)
	db, err := sql.Open("mysql", dsn.Redacted()) // TODO(juagargi) DSN should be a parameter
	// db, err := sql.Open("mysql", "root@tcp(localhost)/fpki") // TODO(juagargi) DSN should be a parameter
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10) // TODO(juagargi) set higher for production
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(2 * time.Second)
	db.SetConnMaxIdleTime(1 * time.Second) // lower or equal than above
	// check schema
	if err := checkSchema(db); err != nil {
		return nil, err
	}
	return &mysqlDB{db: db}, nil
}

func checkSchema(c *sql.DB) error {
	_, err := c.Query("SELECT COUNT(*) FROM nodes")
	if err != nil {
		return fmt.Errorf("table nodes: %w", err)
	}
	return nil
}
