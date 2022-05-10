package db

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOverlappingBits tests the correct functioning of overlappingBits.
func TestOverlappingBits(t *testing.T) {
	cases := map[string]struct {
		a        *big.Int
		b        *big.Int
		overlap  *big.Int
		bitCount int
	}{
		"allEqual": {
			a:        big.NewInt(0b0101),
			b:        big.NewInt(0b0101),
			overlap:  big.NewInt(0b0101),
			bitCount: 256 - 0,
		},
		"last2bitsDifferent": {
			a:        big.NewInt(0b0101),
			b:        big.NewInt(0b0111),
			overlap:  big.NewInt(0b0100),
			bitCount: 256 - 2,
		},
		"last4bitsDifferent": {
			a:        big.NewInt(0b0101),
			b:        big.NewInt(0b1010),
			overlap:  big.NewInt(0b0000),
			bitCount: 256 - 4,
		},
		"allDifferent": {
			a:        biggie(255, "1"),
			b:        biggie(255, "0"),
			overlap:  big.NewInt(0),
			bitCount: 0,
		},
		"bit2different": {
			a:        biggie(255, "01"),
			b:        biggie(255, "00"),
			overlap:  biggie(255, "0"),
			bitCount: 1,
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			overlap, bitCount := overlappingBits(tc.a, tc.b)
			require.Equal(t, tc.overlap, overlap, "overlap different\nexpected: %s \ngot       %s",
				bitString(tc.overlap), bitString(overlap))
			require.Equal(t, tc.bitCount, bitCount)
		})
	}
}

// TestUpdateStructure tests the correct functioning of updateStructure.
// It builds a complete 4 bit tree, by adding nodes in this order:
// 0001
// 0010
// 0011
// 1000
// 1100
// 1110
// 1111
// 0000
func TestUpdateStructure(t *testing.T) {
	root := &node{}

	leaf := big.NewInt(0b0001)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 1)
	require.Equal(t, (*big.Int)(nil), root.id)
	require.NotNil(t, root.left)
	require.Nil(t, root.right)
	require.Equal(t, big.NewInt(0b0001), root.left.id) // depth 1

	leaf = big.NewInt(0b0010)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 2)
	require.Equal(t, (*big.Int)(nil), root.id) // depth 0
	require.NotNil(t, root.left)
	require.Nil(t, root.right)
	require.Equal(t, big.NewInt(0b00), root.left.id) // depth 1
	require.NotNil(t, root.left.left)
	require.NotNil(t, root.left.right)
	require.Equal(t, big.NewInt(0b0001), root.left.left.id) // depth 2
	require.Nil(t, root.left.left.left)
	require.Nil(t, root.left.left.right)
	require.Equal(t, big.NewInt(0b0010), root.left.right.id) // depth 2
	require.Nil(t, root.left.right.left)
	require.Nil(t, root.left.right.right)

	leaf = big.NewInt(0b0011)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 3)
	require.Equal(t, (*big.Int)(nil), root.id)       // depth 0
	require.Equal(t, big.NewInt(0b00), root.left.id) // depth 1
	require.Equal(t, 254, root.left.depth)
	require.Equal(t, big.NewInt(0b0001), root.left.left.id) // depth 2
	require.Equal(t, 256, root.left.left.depth)
	require.Equal(t, big.NewInt(0b0010), root.left.right.id) // depth 2
	require.Equal(t, 255, root.left.right.depth)
	require.Equal(t, big.NewInt(0b0010), root.left.right.left.id) // depth 3
	require.Equal(t, 256, root.left.right.left.depth)
	require.Equal(t, big.NewInt(0b0011), root.left.right.right.id)
	require.Equal(t, 256, root.left.right.right.depth)

	leaf = big.NewInt(0b1000)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 4)
	require.Equal(t, 252, root.left.depth)

	leaf = big.NewInt(0b1100)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 5)

	leaf = big.NewInt(0b1110)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 6)

	leaf = big.NewInt(0b1111)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 7)

	leaf = big.NewInt(0b0000)
	updateStructure(root, leaf)
	checkStructureIsConsistent(t, root, 8)
}

// biggie(255, "1010", 0, "1") sets the 4 most MSB bits to 1010 and the LSB to 1
func biggie(params ...interface{}) *big.Int {
	if len(params)%2 != 0 {
		panic("bad params: bad length")
	}
	ret := big.NewInt(0)
	for i := 0; i < len(params); i += 2 {
		c := params[i].(int)
		s := params[i+1].(string)
		for j := c; j > c-len(s); j-- {
			var b uint
			if s[c-j] == '1' {
				b = 1
			}
			ret.SetBit(ret, j, b)
		}
	}
	return ret
}

// checkStructureIsConsistent checks that each node's children have the node as parent.
// It also checks that the leaves are unique, and that the leaves count is correct.
func checkStructureIsConsistent(t *testing.T, root *node, leafCount int) {
	t.Helper()
	// BFS, children's parent must be this node
	require.Equal(t, 0, root.depth)
	pending := []*node{root}
	uniqueLeafs := make(map[string]*node)
	totalLeafs := 0
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		if current.left != nil {
			require.Equal(t, current, current.left.parent)
			require.Greater(t, current.left.depth, current.depth, "failed at current %s", current)
			pending = append(pending, current.left)
		}
		if current.right != nil {
			require.Equal(t, current, current.right.parent)
			require.Greater(t, current.right.depth, current.depth, "failed at current %s", current)
			pending = append(pending, current.right)
		}
		if current.left == nil && current.right == nil {
			// leaf
			require.Equal(t, 256, current.depth)
			totalLeafs++
			uniqueLeafs[current.String()] = current
		}
	}
	require.Len(t, uniqueLeafs, totalLeafs)
	require.Equal(t, leafCount, totalLeafs)
}
