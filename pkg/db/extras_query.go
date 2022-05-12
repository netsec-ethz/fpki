package db

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"
)

func DeletemeSelectNodes(db DB, count int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])

	for i := 0; i < count; i++ {
		idhash := [32]byte{}
		sequentialHash.FillBytes(idhash[:])
		sequentialHash.Add(sequentialHash, big.NewInt(1))
		row := c.db.QueryRowContext(ctx, "SELECT idhash,value FROM nodes WHERE idhash=?", idhash[:])
		// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
		retIdHash := []byte{}
		var value []byte
		if err := row.Scan(&retIdHash, &value); err != nil {
			return err
		}
		if i%10000 == 0 {
			fmt.Printf("%d / %d\n", i, count)
		}
	}
	return nil
}

// with prepared stmts
func DeletemeSelectNodes2(db DB, count int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])
	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		idhash := [32]byte{}
		sequentialHash.FillBytes(idhash[:])
		sequentialHash.Add(sequentialHash, big.NewInt(1))
		row := prepStmt.QueryRowContext(ctx, idhash[:])
		// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
		retIdHash := []byte{}
		var value []byte
		if err := row.Scan(&retIdHash, &value); err != nil {
			return err
		}
		if i%10000 == 0 {
			fmt.Printf("%d / %d\n", i, count)
		}
	}
	return nil
}

// DeletemeSelectNodes3 has multiple go routines
func DeletemeSelectNodes3(db DB, count int, goroutinesCount int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])
	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%goroutinesCount != 0 {
		panic("logic error")
	}

	wg := sync.WaitGroup{}
	wg.Add(goroutinesCount)
	for r := 0; r < goroutinesCount; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < count/goroutinesCount; i++ {
				idhash := [32]byte{}
				sequentialHash.FillBytes(idhash[:])
				sequentialHash.Add(sequentialHash, big.NewInt(1))
				row := prepStmt.QueryRowContext(ctx, idhash[:])
				// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
				retIdHash := []byte{}
				var value []byte
				if err := row.Scan(&retIdHash, &value); err != nil {
					panic(err)
				}
				if i%10000 == 0 {
					fmt.Printf("%d / %d\n", i, count)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// DeletemeSelectNodesRandom4 has multiple go routines and reads random IDs
func DeletemeSelectNodesRandom4(db DB, count int, goroutinesCount int) error {
	var err error
	c := db.(*mysqlDB)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	randomIDs, err := retrieveIDs(ctx, c, goroutinesCount)
	if err != nil {
		return err
	}

	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%goroutinesCount != 0 {
		panic("logic error: count not divisible by number of routines")
	}

	wg := sync.WaitGroup{}
	wg.Add(goroutinesCount)
	for r := 0; r < goroutinesCount; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < count/goroutinesCount; i++ {
				idhash := randomIDs[rand.Intn(len(randomIDs))]
				row := prepStmt.QueryRowContext(ctx, idhash[:])
				// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
				retIdHash := []byte{}
				var value []byte
				if err := row.Scan(&retIdHash, &value); err != nil {
					panic(err)
				}
				if i%10000 == 0 {
					fmt.Printf("%d / %d\n", i, count)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// DeletemeSelectNodesRandom5 creates `connectionCount` connections with
// `routinesPerConn` go routines per connection.
// returns the time when it started to do actual work, and error
func DeletemeSelectNodesRandom5(count, connectionCount, routinesPerConn int) (time.Time, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	DB, err := Connect()
	if err != nil {
		return time.Time{}, err
	}
	masterConn := DB.(*mysqlDB)
	totalRoutines := connectionCount * routinesPerConn
	randomIDs, err := retrieveIDs(ctx, masterConn, totalRoutines)
	if err != nil {
		return time.Time{}, err
	}
	if err = DB.Close(); err != nil {
		return time.Time{}, err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%totalRoutines != 0 {
		panic(fmt.Sprintf("logic error: count not divisible by number of total routines %d "+
			"round count to %d", totalRoutines, count+count%totalRoutines))
	}

	conns := make([]*mysqlDB, connectionCount)
	for c := 0; c < connectionCount; c++ {
		DB, err := Connect()
		if err != nil {
			return time.Time{}, err
		}
		conns[c] = DB.(*mysqlDB)
	}
	t0 := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(totalRoutines)
	for c := 0; c < connectionCount; c++ {
		cc := c
		go func() {
			conn := conns[cc]
			prepStmt, err := conn.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
			if err != nil {
				panic(err)
			}

			for r := 0; r < routinesPerConn; r++ {
				go func() {
					defer wg.Done()
					for i := 0; i < count/totalRoutines; i++ {
						idhash := randomIDs[rand.Intn(len(randomIDs))]
						row := prepStmt.QueryRowContext(ctx, idhash[:])
						// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
						retIdHash := []byte{}
						var value []byte
						if err := row.Scan(&retIdHash, &value); err != nil {
							panic(err)
						}
						if i%10000 == 0 {
							fmt.Printf("%d / %d\n", i, count)
						}
					}
				}()
			}
		}()
	}

	wg.Wait()
	return t0, nil
}

// DeletemeSelectLeaves performs count retrievals of leaves, monothreaded.
// It is useful to determine the speedup of an alternative approach, such as stored proc.
func DeletemeSelectLeaves(leafCount int) (time.Time, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	t0 := time.Now()
	DB, err := Connect()
	if err != nil {
		return time.Time{}, err
	}
	c := DB.(*mysqlDB)

	randomIDs, err := retrieveLeafIDs(ctx, c, min(leafCount, 100))
	if err != nil {
		return time.Time{}, err
	}
	for i := 0; i < leafCount; i++ {
		for _, leafId := range randomIDs {
			pathFromLeaf, err := getPathFromLeaf(ctx, c, leafId)
			if err != nil {
				panic(err)
			}
			// fmt.Printf("path has %d components\n", len(pathFromLeaf))
			_ = pathFromLeaf
			if i%1000 == 0 {
				fmt.Printf("%d / %d\n", i, leafCount)
			}
			i++
		}
	}
	return t0, nil
}

func DeletemeSelectLeavesStoredProc(leafCount int) (time.Time, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	t0 := time.Now()
	DB, err := Connect()
	if err != nil {
		return time.Time{}, err
	}
	c := DB.(*mysqlDB)

	randomIDs, err := retrieveLeafIDs(ctx, c, min(leafCount, 100))
	if err != nil {
		return time.Time{}, err
	}
	for i := 0; i < leafCount; i++ {
		for _, leafId := range randomIDs {
			row := c.db.QueryRowContext(ctx, "CALL get_leaf(?)", leafId[:])
			var path []byte
			err = row.Scan(&path)
			if err != nil {
				panic(err)
			}
			fmt.Printf("%s\n\n", hex.EncodeToString(path))
			if i%1000 == 0 {
				fmt.Printf("%d / %d\n", i, leafCount)
			}
			i++
		}
	}
	return t0, nil
}

// DeletemeSelectLeavesStoredFunc uses a stored function to retrieve the path from the leave to
// the root of the tree.
// This function is monothreaded.
func DeletemeSelectLeavesStoredFunc(leafCount int) (time.Time, error) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	t0 := time.Now()
	DB, err := Connect()
	if err != nil {
		return time.Time{}, err
	}
	c := DB.(*mysqlDB)

	randomIDs, err := retrieveLeafIDs(ctx, c, min(leafCount, 100))
	if err != nil {
		return time.Time{}, err
	}
	for i := 0; i < leafCount; i++ {
		for _, leafId := range randomIDs {
			row := c.db.QueryRowContext(ctx, "SELECT node_path(?)", leafId[:])
			var path []byte
			err = row.Scan(&path)
			if err != nil {
				panic(err)
			}
			// fmt.Printf("%s\n\n", hex.EncodeToString(path))
			if i%1000 == 0 {
				fmt.Printf("%d / %d\n", i, leafCount)
			}
			i++
		}
	}
	return t0, nil
}

func DeletemeSelectLeavesStoredFunc2(leafCount, connectionCount, routinesPerConn int) (
	time.Time, error) {

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	DB, err := Connect()
	if err != nil {
		return time.Time{}, err
	}
	c := DB.(*mysqlDB)
	totalRoutines := connectionCount * routinesPerConn
	randomIDs, err := retrieveLeafIDs(ctx, c, min(leafCount, 100))
	if err != nil {
		return time.Time{}, err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if leafCount%totalRoutines != 0 {
		panic(fmt.Sprintf("logic error: count not divisible by number of total routines %d "+
			"round count to %d", totalRoutines, leafCount+leafCount%totalRoutines))
	}
	conns := make([]*mysqlDB, connectionCount)
	for c := 0; c < connectionCount; c++ {
		DB, err := Connect()
		if err != nil {
			return time.Time{}, err
		}
		conns[c] = DB.(*mysqlDB)
	}

	t0 := time.Now()
	wg := sync.WaitGroup{}
	wg.Add(totalRoutines)
	for c := 0; c < connectionCount; c++ {
		cc := c
		go func() {
			conn := conns[cc]
			prepStmt, err := conn.db.Prepare("SELECT node_path(?)")
			if err != nil {
				panic(err)
			}

			for r := 0; r < routinesPerConn; r++ {
				go func() {
					defer wg.Done()
					for i := 0; i < leafCount/totalRoutines; i++ {
						idhash := randomIDs[rand.Intn(len(randomIDs))]
						row := prepStmt.QueryRowContext(ctx, idhash[:])
						// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
						var path []byte
						if err := row.Scan(&path); err != nil {
							panic(err)
						}
						if i%10000 == 0 {
							fmt.Printf("%d / %d\n", i, leafCount)
						}
					}
				}()
			}
		}()
	}

	wg.Wait()
	return t0, nil
}
