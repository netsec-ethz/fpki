package db

import "fmt"

func (c *mysqlDB) DisableKeys() error {
	_, err := c.db.Exec("ALTER TABLE `tree` DISABLE KEYS")
	if err != nil {
		return fmt.Errorf("DisableKeys | DISABLE KEYS")
	}

	_, err = c.db.Exec("SET UNIQUE_CHECKS =0")
	if err != nil {
		return fmt.Errorf("DisableKeys | UNIQUE_CHECKS KEYS")
	}

	return nil
}

func (c *mysqlDB) EnableKeys() error {
	_, err := c.db.Exec("ALTER TABLE `tree` ENABLE KEYS")
	if err != nil {
		return fmt.Errorf("DisableKeys | ENABLE KEYS")
	}

	_, err = c.db.Exec("SET UNIQUE_CHECKS =1")
	if err != nil {
		return fmt.Errorf("DisableKeys | UNIQUE_CHECKS KEYS")
	}

	return nil
}
