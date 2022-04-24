package mysql_mapstore

import (
	"fmt"
	"strconv"
	"testing"
	"time"
)

func Test_MYSQL(t *testing.T) {
	// create a map store
	mapSQLStore, _, err := InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map?multiStatements=true", "11111")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	// insert 10000 entries in the store
	for i := 0; i < 10000; i++ {
		err = mapSQLStore.Set([]byte(strconv.FormatInt(int64(i), 10)), []byte("Im the hihih"))
		if err != nil {
			t.Errorf(err.Error())
			return
		}
	}

	// export data in the store to the DB
	start := time.Now()
	err = mapSQLStore.SaveValueMapToDB()
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	end := time.Now()
	fmt.Println(end.Sub(start))

	// read from previously stored data
	start = time.Now()
	mapSQLStore, _, err = InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map?multiStatements=true", "11111")
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	end = time.Now()
	fmt.Println(end.Sub(start))

	// check if the storing and reading is correct
	for i := 0; i < 10000; i++ {
		_, err = mapSQLStore.Get([]byte(strconv.FormatInt(int64(i), 10)))
		if err != nil {
			t.Errorf(err.Error())
			return
		}
	}
}
