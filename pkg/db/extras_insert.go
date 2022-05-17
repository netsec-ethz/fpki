package db

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
)

func DeletemeDropAllNodes(db Conn) error {
	c := db.(*mysqlDB)
	_, err := c.db.Exec("DELETE FROM nodes")
	return err
}

func DeletemeCreateNodes(db Conn, count int) error {
	c := db.(*mysqlDB)
	_, err := c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	if err != nil {
		return fmt.Errorf("disabling keys: %w", err)
	}
	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	for i := 0; i < count; i++ {
		_, err = c.db.Exec("INSERT INTO nodes VALUES(?,?)", i, blob)
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i, count)
		}
	}
	_, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	if err != nil {
		return fmt.Errorf("enabling keys: %w", err)
	}
	return nil
}

func DeletemeCreateNodesBulk(db Conn, count int) error {
	c := db.(*mysqlDB)
	// _, err := c.db.Exec("ALTER TABLE `nodes` DROP INDEX PRIMARY")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }
	_, err := c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// stmt, err := c.db.Prepare("INSERT IGNORE INTO nodes (idnodes,value) VALUES(?,?)")
	stmt, err := c.db.Prepare("INSERT IGNORE INTO nodes (value) VALUES(?)")
	if err != nil {
		panic("logic error")
	}
	for i := 0; i < count; i++ {
		// _, err = c.db.Exec("INSERT IGNORE INTO nodes VALUES(?,?)", i, blob)
		// _, err = c.db.Exec("INSERT INTO nodes (value) VALUES(?)", blob)
		_, err = stmt.Exec(blob)
		if err != nil {
			return err
		}
		if i%1000 == 0 {
			fmt.Printf("%d/%d\n", i, count)
		}
	}

	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

func DeletemeCreateNodesBulk2(db Conn, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (value) VALUES " + repeatStmt(N, 1)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}
	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, N) // 1 elements per record ()
		for j := 0; j < N; j++ {
			data[j] = blob
		}
		_, err = stmt.Exec(data...)
		return err
	}
	// hash := big.Int{}
	// hash.Bits()
	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}
	// TODO(juagargi) insert the count%N remaining records

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

var initialSequentialHash = *((&big.Int{}).Exp(big.NewInt(2), big.NewInt(200), nil))

// - inserts BLOBS of values
// - inserts hashes of 32 bytes as indices
func DeletemeCreateNodesBulk3(db Conn, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (idhash,value) VALUES " + repeatStmt(N, 2)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}

	sequentialHash := (&big.Int{}).Add(&initialSequentialHash, big.NewInt(0))
	bigOne := big.NewInt(1)

	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, 2*N) // 2 elements per record ()
		for j := 0; j < N; j++ {
			// ID hash
			idhash := [32]byte{}
			// _, err = rand.Read(idhash[:])

			sequentialHash.Add(sequentialHash, bigOne)
			sequentialHash.FillBytes(idhash[:])
			// sequentialHash.Bits()

			data[2*j] = idhash[:]
			data[2*j+1] = blob
			// fmt.Printf("%s\n", hex.EncodeToString(idhash[:]))
		}
		_, err = stmt.Exec(data...)
		return err
	}

	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

// - inserts BLOBS of values
// - inserts hashes of 32 bytes as indices, random value
func DeletemeCreateNodesBulk4(db Conn, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (idhash,value) VALUES " + repeatStmt(N, 2)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}

	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, 2*N) // 2 elements per record ()
		for j := 0; j < N; j++ {
			// ID hash
			idhash := [32]byte{}
			_, err = rand.Read(idhash[:])

			data[2*j] = idhash[:]
			data[2*j+1] = blob
			// fmt.Printf("%s\n", hex.EncodeToString(idhash[:]))
		}
		_, err = stmt.Exec(data...)
		return err
	}

	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

// DeletemeCreateNodes2 where count is the number of leaves.
// It adds a value (0xDEADBEEF) and a proof (idhash[1:]) to each node.
func DeletemeCreateNodes2(db Conn, count int) error {
	var err error
	c := db.(*mysqlDB)

	root := &node{
		id:    big.NewInt(0),
		depth: 0,
	}
	uniqueLeaves := make(map[[32]byte]struct{})
	for i := 0; i < count; i++ {
		var idhash [32]byte
		if _, err = rand.Read(idhash[:]); err != nil {
			return err
		}
		if _, ok := uniqueLeaves[idhash]; ok {
			panic("duplicate random ID")
		}
		uniqueLeaves[idhash] = struct{}{}
		updateStructureRaw(root, idhash)
	}
	dups := findDuplicates(root) // deleteme
	if len(dups) > 0 {
		fmt.Printf("%d duplicates found\n", len(dups))
		for id, d := range dups {
			fmt.Printf("ID: [%s] %2d nodes\n", hex.EncodeToString(id[:]), len(d))
			for i, c := range d {
				fmt.Printf("\t[%2d] depth %d\n\n", i, c.depth)
				tempId := c.FullID()
				fmt.Printf("\thex: %s\n\tbits: %s\n",
					hex.EncodeToString(tempId[1:]), bitString(c.id))
				fmt.Println(pathToString(pathFromNode(c)))
			}
		}
		panic("duplicates")
	}
	if err = insertIntoDB2(c, root); err != nil {
		return err
	}
	return nil
}
