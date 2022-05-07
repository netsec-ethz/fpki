package batchedsmt

// DefaultLeaf value
var (
	DefaultLeaf = Hasher([]byte{0x0})
)

// HashLength length of the hash
// TreeHeight height of the tree
const (
	HashLength = 32
	TreeHeight = 256
)

// Hash length of the hash
type Hash [HashLength]byte
