package db

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Flatten truncates the leaves table, and adds all the existing leaves from the nodes table.
// It uses the flatten_subtree stored procedure for this.
// The parameter depth specifies the depth to use to retrieve the subtrees to be flatten:
// e.g. a depth=1 indicates 2^3=8 subtrees being flatten in parallel.
func Flatten(ctx context.Context, createConn func() (Conn, error), depth int) error {
	t0 := time.Now()
	// prepare session
	masterConn, err := createConn()
	if err != nil {
		return fmt.Errorf("cannot create initial connection: %w", err)
	}
	if _, err = masterConn.DB().Exec("SET max_sp_recursion_depth = 255"); err != nil {
		return fmt.Errorf("cannot set the recursion depth: %w", err)
	}

	if _, err = masterConn.DB().Exec("BEGIN"); err != nil {
		return fmt.Errorf("cannot begin a transaction: %w", err)
	}
	// XXX(juagargi) DO NOT remove the index and recreate it again.
	// Performance is better if we keep the index because the cost of inserting into
	// a sorted index in log N, N times, BUT IN 64 THREADS, while we don't know how to
	// recreate an index using multiple threads.
	if _, err = masterConn.DB().Exec("TRUNCATE leaves"); err != nil {
		return fmt.Errorf("cannot truncate the leaves table: %w", err)
	}

	var left, right, proof []byte
	row := masterConn.DB().QueryRow("SELECT leftnode,rightnode,proof FROM root")
	if err = row.Scan(&left, &right, &proof); err != nil {
		return fmt.Errorf("cannot query the root node: %w", err)
	}

	// retrieve depth levels of subtrees
	type subtree struct {
		id         [33]byte
		proofchain []byte
	}
	subtrees := []subtree{}
	if left != nil {
		var id [33]byte
		copy(id[:], left)
		subtrees = append(subtrees, subtree{
			id:         id,
			proofchain: proof,
		})
	}
	if right != nil {
		var id [33]byte
		copy(id[:], right)
		subtrees = append(subtrees, subtree{
			id:         id,
			proofchain: proof,
		})
	}
	for i := 1; i < depth; i++ {
		nextlevel := []subtree{}
		for len(subtrees) > 0 {
			t := subtrees[0]
			subtrees = subtrees[1:]
			// explore this tree and add its children to nextlevel
			row := masterConn.DB().QueryRow("SELECT leftnode,rightnode,proof FROM nodes WHERE idhash=?",
				t.id[:])
			if err = row.Scan(&left, &right, &proof); err != nil {
				return fmt.Errorf("cannot query the nodes table for id %s: %w",
					hex.EncodeToString(t.id[:]), err)
			}
			if left != nil {
				var id [33]byte
				copy(id[:], left)
				nextlevel = append(nextlevel, subtree{
					id:         id,
					proofchain: append(t.proofchain, proof...),
				})
			}
			if right != nil {
				var id [33]byte
				copy(id[:], right)
				nextlevel = append(nextlevel, subtree{
					id:         id,
					proofchain: append(t.proofchain, proof...),
				})
			}
		}
		// copy all from nextlevel to subtrees
		subtrees = nextlevel
	}

	fmt.Printf("flattening the tree with %d routines ... (elapsed %s)\n",
		len(subtrees), time.Since(t0))
	// we need a new conn for each element in subtrees
	conns := make([]Conn, len(subtrees))
	wg := sync.WaitGroup{}
	wg.Add(len(subtrees))
	errs := make(chan error, len(subtrees))
	for i, t := range subtrees {
		i, t := i, t
		conns[i], err = createConn()
		if err != nil {
			return fmt.Errorf("cannot create connection per subtree (%d): %w", i, err)
		}
		go func() {
			defer wg.Done()

			c := conns[i]
			if _, err = c.DB().Exec("SET max_sp_recursion_depth = 255"); err != nil {
				errs <- fmt.Errorf("cannot set recursion level in subtree connection: %w", err)
			}
			if _, err = c.DB().Exec("SET autocommit=0"); err != nil {
				errs <- fmt.Errorf("cannot disable autocommit: %w", err)
			}
			if _, err = c.DB().Exec("SET innodb_table_locks=0"); err != nil {
				errs <- fmt.Errorf("cannot disable innodb locks: %w", err)
			}

			if err = c.FlattenSubtree(ctx, t.id, t.proofchain); err != nil {
				errs <- fmt.Errorf("error executing flatten stored proc.: %w", err)
			}
			if _, err = c.DB().Exec("COMMIT"); err != nil {
				errs <- fmt.Errorf("cannot commit in subtree connection: %w", err)
			}
		}()
	}
	wg.Wait()
	select {
	case err = <-errs:
		return err
	default:
	}
	if _, err = masterConn.DB().Exec("COMMIT"); err != nil {
		return fmt.Errorf("cannot commit the transaction: %w", err)
	}
	if err = masterConn.Close(); err != nil {
		return fmt.Errorf("cannot close the initial connection: %w", err)
	}
	return nil
}
