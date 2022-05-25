package db

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/go-sql-driver/mysql"
)

func toSlice(id [33]byte) []byte {
	return id[:]
}

func repeatStmt(N int, noOfComponents int) string {
	components := make([]string, noOfComponents)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", N-1) + toRepeat
}

func retrieveIDs(ctx context.Context, c *mysqlDB, count int) ([][32]byte, error) {
	rows, err := c.db.QueryContext(ctx, "SELECT idhash FROM nodes LIMIT ?", count)
	if err != nil {
		return nil, err
	}
	ids := make([][32]byte, count)
	for i := 0; i < count; i++ {
		if !rows.Next() {
			return nil, fmt.Errorf("wrong number of IDs retrieved, at iteration %d", i)
		}
		var slice []byte
		if err = rows.Scan(&slice); err != nil {
			return nil, err
		}
		copy(ids[i][:], slice)
	}
	return ids, nil
}

func retrieveLeafIDs(ctx context.Context, c *mysqlDB, count int) ([][33]byte, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT idhash FROM nodes WHERE LEFT(idhash,1) = UNHEX("FF") LIMIT ?`, count)
	if err != nil {
		return nil, err
	}
	ids := make([][33]byte, count)
	for i := 0; i < count; i++ {
		if !rows.Next() {
			return nil, fmt.Errorf("wrong number of IDs retrieved, at iteration %d", i)
		}
		var slice []byte
		if err = rows.Scan(&slice); err != nil {
			return nil, err
		}
		copy(ids[i][:], slice)
	}
	return ids, nil
}

func insertIntoDB(c *mysqlDB, root *node) error {
	// var err error
	// _, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	// if err != nil {
	// 	return err
	// }
	// _, err = c.db.Exec("SET autocommit=0") // XXX(juagargi) this seems to cause some trouble by omitting some records
	// if err != nil {
	// 	return err
	// }
	// _, err = c.db.Exec("ALTER TABLE nodes DROP INDEX idhash; ;")
	// if err != nil {
	// 	return err
	// }

	N := 1000

	repeatedStmt := "INSERT INTO nodes (idhash,parentnode,leftnode,rightnode,value) VALUES " + repeatStmt(N, 5)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic(err)
	}
	pending := make([]*node, 0) // XXX(juagargi) !!!! this queue is not memory efficient
	// the root node will not be inserted into the table (performance reasons), and thus, its
	// two children cannot point to it. They will point to null.
	if root.left != nil {
		root.left.parent = nil
		pending = append(pending, root.left)
	}
	if root.right != nil {
		root.right.parent = nil
		pending = append(pending, root.right)
	}
	total := 0
	nodes := make([]*node, 0, N)
	for i := 0; len(pending) > 0; i++ {
		total++
		if total%10000 == 0 {
			fmt.Printf("inserted %7d\n", total)
		}
		current := pending[0]
		pending = pending[1:]
		if current.left != nil {
			pending = append(pending, current.left)
		}
		if current.right != nil {
			pending = append(pending, current.right)
		}

		if len(nodes) == N {
			// send to DB
			if err := nodeBatchToDB(c, stmt, nodes); err != nil {
				return err
			}
			// clear
			nodes = make([]*node, 0, N)
			i = -1
		}
		nodes = append(nodes, current)
	}
	// remaining less than N-1 ones:
	if len(nodes) > 0 {
		repeatedStmt = "INSERT INTO nodes (idhash,parentnode,leftnode,rightnode,value) VALUES " +
			repeatStmt(len(nodes), 5)
		stmt, err = c.db.Prepare(repeatedStmt)
		if err != nil {
			panic(err)
		}
		if err := nodeBatchToDB(c, stmt, nodes); err != nil {
			return err
		}
	}

	// _, err = c.db.Exec("COMMIT")
	// if err != nil {
	// 	return err
	// }
	// _, err = c.db.Exec("ALTER TABLE nodes ADD UNIQUE INDEX idhash (idhash ASC) VISIBLE; ;")
	// if err != nil {
	// 	return err
	// }
	// _, err = c.db.Exec("UNLOCK TABLES")
	// if err != nil {
	// 	return err
	// }
	return nil
}

// insertIntoDB2 inserts 6 columns (idhash,parent,left,right,value,proof) in batches of 1000.
func insertIntoDB2(c *mysqlDB, root *node) error {
	N := 1000

	err := replaceRoot(c, root)
	if err != nil {
		return err
	}

	repeatedStmt := "INSERT INTO nodes (idhash,parentnode,leftnode,rightnode,value,proof) VALUES " + repeatStmt(N, 6)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic(err)
	}
	// the root node is not inserted into the nodes table (performance reasons), and thus, its
	// two children cannot point to it. They will point to null.
	pending := make([]*node, 0) // XXX(juagargi) !!!! this queue is not memory efficient
	if root.left != nil {
		root.left.parent = nil
		pending = append(pending, root.left)
	}
	if root.right != nil {
		root.right.parent = nil
		pending = append(pending, root.right)
	}
	total := 0
	nodes := make([]*node, 0, N)
	for i := 0; len(pending) > 0; i++ {
		total++
		if total%10000 == 0 {
			fmt.Printf("inserted %7d\n", total)
		}
		current := pending[0]
		pending = pending[1:]
		if current.left != nil {
			pending = append(pending, current.left)
		}
		if current.right != nil {
			pending = append(pending, current.right)
		}

		if len(nodes) == N {
			// send to DB
			if err := nodeBatchToDB2(c, stmt, nodes); err != nil {
				return err
			}
			// clear
			nodes = make([]*node, 0, N)
			i = -1
		}
		nodes = append(nodes, current)
	}
	// remaining less than N-1 ones:
	if len(nodes) > 0 {
		repeatedStmt = "INSERT INTO nodes (idhash,parentnode,leftnode,rightnode,value,proof) VALUES " +
			repeatStmt(len(nodes), 6)
		stmt, err = c.db.Prepare(repeatedStmt)
		if err != nil {
			panic(err)
		}
		if err := nodeBatchToDB2(c, stmt, nodes); err != nil {
			return err
		}
	}
	return nil
}

// createCSVFile returns the path of the CSV file
func createCSVFile(root *node) (string, error) {
	// function to convert a node into a row in a CSV:
	nodeToStringSlice := func(n *node) []string {
		var xleft, xright, xparent []byte
		if n.parent != nil {
			xparent = toSlice(n.parent.FullID())
		}
		if n.left != nil {
			xleft = toSlice(n.left.FullID())
		}
		if n.right != nil {
			xright = toSlice(n.right.FullID())
		}
		xvalue := []byte{0xde, 0xad, 0xbe, 0xef}
		xproof := n.FullID()
		return []string{
			hex.EncodeToString(toSlice(n.FullID())),
			hex.EncodeToString(xparent),
			hex.EncodeToString(xleft),
			hex.EncodeToString(xright),
			hex.EncodeToString(xvalue),
			hex.EncodeToString(xproof[:]),
		}
	}

	// initialize CSV with the header
	f, err := os.CreateTemp("", "fpki_nodes")
	if err != nil {
		panic(err)
	}
	w := csv.NewWriter(f)
	err = w.Write([]string{"idhash", "parentnode", "leftnode", "rightnode", "value", "proof"})
	if err != nil {
		panic(err)
	}

	// do the rest of nodes
	pending := []*node{}
	if root.left != nil {
		// avoid the root from being present at all in the nodes table by removing all references:
		root.left.parent = nil
		// add the child
		pending = append(pending, root.left)
	}
	if root.right != nil {
		// avoid the root from being present at all in the nodes table by removing all references:
		root.right.parent = nil
		// add the child
		pending = append(pending, root.right)
	}
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		if current.left != nil {
			pending = append(pending, current.left)
		}
		if current.right != nil {
			pending = append(pending, current.right)
		}
		err := w.Write(nodeToStringSlice(current))
		if err != nil {
			panic(err)
		}
	}
	w.Flush()
	if err := f.Close(); err != nil {
		panic(err)
	}
	return f.Name(), nil
}

func insertIntoDBWithFile(c *mysqlDB, filepath string) error {
	// send to DB
	mysql.RegisterLocalFile(filepath)
	_, err := c.DB().Exec("SET GLOBAL local_infile=1")
	if err != nil {
		panic(err)
	}
	_, err = c.DB().Exec(`LOAD DATA LOCAL INFILE ? INTO TABLE nodes `+
		`FIELDS TERMINATED BY ',' ENCLOSED BY '"' `+
		`LINES TERMINATED BY '\n' `+
		`IGNORE 1 ROWS `+
		`(@idhash,@parentnode,@leftnode,@rightnode,@value,@proof) `+
		`SET idhash = UNHEX(@idhash),`+
		`parentnode = UNHEX(@parentnode),`+
		`leftnode = UNHEX(@leftnode),`+
		`rightnode = UNHEX(@rightnode),`+
		`value = UNHEX(@value),`+
		`proof = UNHEX(@proof)`, filepath)
	if err != nil {
		panic(err)
	}

	// remove temp file only if the insertion finished without errors:
	os.Remove(filepath)
	return nil
}

// nodeBatchToDB creates the data structure to be pushed to the DB, from a slice of nodes.
// It expects the root node not to be present in the collection.
func nodeBatchToDB(c *mysqlDB, stmt *sql.Stmt, nodes []*node) error {
	toSlice := func(id [33]byte) []byte {
		return id[:]
	}
	cryptoMaterialMock, _ := hex.DecodeString("deadbeef")
	data := make([]interface{}, 5*len(nodes))
	for i := 0; i < len(nodes); i++ {
		n := nodes[i]
		data[5*i] = toSlice(n.FullID())
		// fmt.Printf("%4d ID: %s\n", i, hex.EncodeToString(toSlice(n.FullID())))
		if n.parent != nil {
			data[5*i+1] = toSlice(n.parent.FullID())
		}
		if n.left != nil {
			data[5*i+2] = toSlice(n.left.FullID())
		}
		if n.right != nil {
			data[5*i+3] = toSlice(n.right.FullID())
		}
		data[5*i+4] = cryptoMaterialMock
	}
	if _, err := stmt.Exec(data...); err != nil {
		return fmt.Errorf("executing prep. statement: %w", err)
	}
	return nil
}

// nodeBatchToDB2 uses 6 columns.
func nodeBatchToDB2(c *mysqlDB, stmt *sql.Stmt, nodes []*node) error {
	cryptoMaterialMock, _ := hex.DecodeString("deadbeef")
	data := make([]interface{}, 6*len(nodes))
	for i := 0; i < len(nodes); i++ {
		n := nodes[i]
		data[6*i] = toSlice(n.FullID())
		if n.parent != nil {
			data[6*i+1] = toSlice(n.parent.FullID())
		}
		if n.left != nil {
			data[6*i+2] = toSlice(n.left.FullID())
		}
		if n.right != nil {
			data[6*i+3] = toSlice(n.right.FullID())
		}
		data[6*i+4] = cryptoMaterialMock
		data[6*i+5] = toSlice(n.FullID())[1:] // proof
	}
	if _, err := stmt.Exec(data...); err != nil {
		return fmt.Errorf("executing prep. statement: %w", err)
	}
	return nil
}

// getRecord returns parent, value, or error
func getRecord(ctx context.Context, c *mysqlDB, id [33]byte) ([]byte, []byte, error) {
	slice := make([]byte, len(id))
	copy(slice, id[:])
	// fmt.Printf("select for %s\n", hex.EncodeToString(slice))
	row := c.db.QueryRowContext(ctx, "SELECT idhash,parentnode,value FROM nodes WHERE idhash=?",
		slice)
	var idFromDB []byte
	var parentID []byte
	var value []byte
	if err := row.Scan(&idFromDB, &parentID, &value); err != nil {
		return nil, nil, err
	}
	return parentID, value, nil
}

// getPathFromLeaf returns the path leaf to root or error
func getPathFromLeaf(ctx context.Context, c *mysqlDB, leafId [33]byte) ([][33]byte, error) {
	id := leafId
	path := [][33]byte{id}
	for {
		parent, _, err := getRecord(ctx, c, id)
		// fmt.Printf("id: %s parent: %s\n", hex.EncodeToString(id[:]), hex.EncodeToString(parent))
		if err != nil {
			return nil, err
		}
		var parentID [33]byte
		copy(parentID[:], parent)
		path = append(path, parentID)
		if parent == nil {
			break
		}
		id = parentID
	}
	return path, nil
}

func replaceRoot(c *mysqlDB, root *node) error {
	// insert the root node apart (see below)
	_, err := c.db.Exec("TRUNCATE root")
	if err != nil {
		return err
	}
	var xleft, xright []byte
	if root.left != nil {
		xleft = toSlice(root.left.FullID())
	}
	if root.right != nil {
		xright = toSlice(root.right.FullID())
	}
	_, err = c.db.Exec("INSERT INTO root (leftnode,rightnode,value,proof) VALUES (?,?,?,?)",
		xleft,
		xright,
		[]byte("root value"),
		[]byte("root proof"))

	return err
}
