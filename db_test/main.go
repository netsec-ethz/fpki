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

	err = db.DeletemeCreateNodes(c)
	if err != nil {
		panic(err)
	}
	fmt.Println("ready")

	// deleteme:

}
