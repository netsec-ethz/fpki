package db

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
)

type node struct {
	id          *big.Int // MSB is index 255, LSB and last bit is at 0
	depth       int      // leafs at 256, root at 0
	parent      *node
	left, right *node
}

func (n node) String() string { // deleteme ?
	if n.id == nil {
		return "  0"
	}
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
			*next = &node{
				id:     leafId,
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
