package db

import "fmt"

func DeletemeCreateNodes(db DB) error {
	c := db.(*mysqlDB)
	res, err := c.db.Exec("INSERT INTO nodes VALUES(?)", 1)
	if err != nil {
		return err
	}
	noRows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	lastId, err := res.LastInsertId()
	if err != nil {
		return err
	}
	fmt.Printf("rowsAffected=%v, lastInsertId=%v\n", noRows, lastId)
	return nil
}
