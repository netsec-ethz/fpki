package db

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
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
	depth       int      // leafs at 256, root at 0
	parent      *node
	left, right *node
}

func (n node) String() string {
	return fmt.Sprintf("%3d %s", n.depth, bitString(n.id)[:n.depth])
}

func DeletemeCreateNodes2(db DB, count int) error {
	var err error
	c := db.(*mysqlDB)

	root := &node{}
	for i := 0; i < count; i++ {
		var idhash [32]byte
		if _, err = rand.Read(idhash[31:]); err != nil {
			return err
		}
		fmt.Printf("id: %s\n", hex.EncodeToString(idhash[:]))
		updateStructureRaw(root, idhash)
	}
	_ = c
	return nil
}

func updateStructureRaw(root *node, leafHash [32]byte) {
	id := big.NewInt(0).SetBytes(leafHash[:])
	updateStructure(root, id)
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
			leafIdCopy := big.NewInt(0)
			leafIdCopy.SetBytes(leafId.Bytes()) // store a copy (not the original pointer)
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
