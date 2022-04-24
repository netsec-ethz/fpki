package mysql_mapstore

import (
	"fmt"
	"testing"
	"time"
)

func Test_MYSQL(t *testing.T) {
	mapSQLStore, err := InitMapSQLStore("root:@tcp(127.0.0.1:3306)/map", "111")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = mapSQLStore.Set([]byte("hi this is a test"), []byte("I'm the content, how are you my friend"))
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	err = mapSQLStore.Set([]byte("hi this is a test"), []byte("I'm"))
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	resultBytes, err := mapSQLStore.Get([]byte("hi this is a test"))
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Println(string(resultBytes))

	start := time.Now()
	err = mapSQLStore.FetchAll()
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	end := time.Now()
	fmt.Println(end.Sub(start))
}
