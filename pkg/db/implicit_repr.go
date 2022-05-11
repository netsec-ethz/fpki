package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
)

// node represents a node in our sparse Merkle tree.
// node contains a pointer (!!!) to a big Int. When setting it, be sure to create a unique copy
// that won't be altered outside this tree.
// node contains the depth of this node in the virtual Merkle tree. That is, depth represents
// the number of bits from the Id that are valid to represent this node.
// node also contains two pointers to possible children (left, right), and one to a parent.
// All nodes have a parent except the root node.
type node struct {
	id          *big.Int // MSB is index 255, LSB and last bit is at 0
	depth       int      // leafs at 256, root at 0. Total: 257 values
	parent      *node
	left, right *node
}

func (n node) String() string {
	return fmt.Sprintf("%3d %s", n.depth, bitString(n.id)[:n.depth])
}

// FullID fills in a 33 byte array with the depth of the node and its ID.
// Byte 0 contains the depth.
// Bytes 1-32 contain the 32 byte ID. The MSB of the ID is at byte 1, the LSB at byte 32.
func (n *node) FullID() [33]byte {
	var id [33]byte
	if n.depth == 0 {
		// this is the root node, it should never be serialized to DB and thus
		// it should never return [33]byte as ID (because depth-1 is negative)
		panic("FullID called on root node")
	}
	id[0] = byte(n.depth - 1)
	n.id.FillBytes(id[1:])
	return id
}

// DeletemeCreateNodes2 where cound is the number of leaves
func DeletemeCreateNodes2(db DB, count int) error {
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
	if err = insertIntoDB(c, root); err != nil {
		return err
	}
	return nil
}

func updateStructureRaw(root *node, leafHash [32]byte) {
	id := big.NewInt(0).SetBytes(leafHash[:])
	updateStructure(root, id)
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

func updateStructure(root *node, leafId *big.Int) {
	currentNode := root
	for i := 255; i >= 0; i-- {
		right := leafId.Bit(i) == 1
		var next **node
		if right {
			next = &currentNode.right
		} else {
			next = &currentNode.left
		}
		if *next == nil {
			leafIdCopy := big.NewInt(0).Set(leafId) // store a copy (not the original pointer)
			*next = &node{
				id:     leafIdCopy,
				depth:  256,
				parent: currentNode,
			}
			return
		}
		overlap, overlapCount := overlappingBits((*next).id, leafId)
		overlapCount = min(overlapCount, (*next).depth)

		if i < 255-overlapCount {
			panic(fmt.Errorf("logic error. i=%d, overlapCount=%d", i, overlapCount))
		}
		i = 255 - overlapCount + 1 // so next iteration extracts the first different bit
		if (*next).depth <= overlapCount {
			// no replacement necessary: simply step into this node
			currentNode = *next
			continue
		}
		// create intermediate node, it will be the parent of "next"
		node := &node{
			depth:  overlapCount,
			id:     overlap,
			parent: currentNode,
		}
		// copy next
		child := *next
		if right {
			currentNode.right = node
		} else {
			currentNode.left = node
		}
		if child.id.Bit(256-overlapCount-1) == 1 {
			node.right = child // the old child is at the right
		} else {
			node.left = child
		}
		child.parent = node
		// current visited node is the newly created one
		currentNode = node
	}
}

// retrieve will return the path from the root to the node with that ID, or nil
func retrieve(root *node, leafId *big.Int) []*node {
	path := []*node{root}
	currentNode := root
	for i := 255; i >= 0; i-- {
		right := leafId.Bit(i) == 1
		if right {
			currentNode = currentNode.right
		} else {
			currentNode = currentNode.left
		}
		if currentNode == nil {
			return nil
		}
		path = append(path, currentNode)
		if currentNode.depth == 256 {
			if currentNode.id.Cmp(leafId) == 0 {
				return path
			}
			return nil
		}

		_, overlapCount := overlappingBits(currentNode.id, leafId)
		if overlapCount < currentNode.depth {
			return nil
		}
		i = 255 - currentNode.depth + 1
	}
	// we should have found a path ending on a leaf or a nil
	panic("logic error")
}

// overlappingBits returns the part of the two IDs that is the same, starting from
// the MSB bit, and the number of bits of overlap
// overlap(0101, 0111) ->  0100,2
// overlap(0101, 0101) ->  0101,4
func overlappingBits(x, y *big.Int) (*big.Int, int) {
	overlap := big.NewInt(0)
	for i := 255; i >= 0; i-- {
		bx := x.Bit(i)
		if bx != y.Bit(i) {
			return overlap, 255 - i
		}
		overlap.SetBit(overlap, i, bx)
	}
	return overlap, 256
}

// bitString represents a big.Int as a string of bits.
func bitString(n *big.Int) string {
	s := make([]byte, 256)
	for i := 255; i >= 0; i-- {
		switch n.Bit(i) {
		case 0:
			s[255-i] = '0'
		case 1:
			s[255-i] = '1'
		}
	}
	return string(s)
}

func min(a int, b ...int) int {
	min := a
	for _, x := range b {
		if x < min {
			min = x
		}
	}
	return min
}

func findDuplicates(root *node) map[[33]byte][]*node {
	pending := []*node{}
	if root.left != nil {
		pending = append(pending, root.left)
	}
	if root.right != nil {
		pending = append(pending, root.right)
	}

	seen := make(map[[33]byte][]*node)
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		if c.left != nil {
			pending = append(pending, c.left)
		}
		if c.right != nil {
			pending = append(pending, c.right)
		}
		id := c.FullID()
		seen[id] = append(seen[id], c)
	}
	dups := make(map[[33]byte][]*node)
	for id, nodes := range seen {
		if len(nodes) > 1 {
			dups[id] = nodes
		}
	}
	return dups
}

func pathFromNode(n *node) []*node {
	path := []*node{}
	for n != nil {
		path = append(path, n)
		n = n.parent
	}
	// reverse
	len := len(path)
	for i := 0; i < len/2; i++ {
		path[i], path[len-i-1] = path[len-i-1], path[i]
	}
	return path
}

func pathToString(path []*node) string {
	steps := make([]string, len(path))
	for i, n := range path {
		steps[i] = n.String()
	}
	return strings.Join(steps, "\n\u2193\n") // concat with down arrow
}
