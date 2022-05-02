package main

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/db"
)

func main() {
	fmt.Println("hello")
	c, err := db.Connect()
	if err != nil {
		panic(err)
	}
	defer c.Close()

	err = c.TestCreateData()
	if err != nil {
		panic(err)
	}
	fmt.Println("ready")
}
