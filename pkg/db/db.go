package db

import "database/sql"

type DB interface {
	Close() error
}

type mysqlDB struct {
	db *sql.DB
}

func (db *mysqlDB) Close() error {
	return db.db.Close()
}
