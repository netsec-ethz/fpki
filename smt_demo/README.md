# SMT Demo
This is a demo for the efficient and database-supported SMT implementation.

Key and value stored in the SMT should be 32 bytes(using SHA256). Before using the SMT library, you should hash the key and values, and sort the key-value pair by hashed keys from low to high, before adding the pairs. One pair should be (32bytes, 32bytes), and the order should be (000,XXX), (001, XXX), (100, XXX), (111,XXX)

## Functions
```
// NewSMT creates a new SMT given a root and a hash function.
// for an empty SMT, root can be nil
func NewTrie(root []byte, hash func(data ...[]byte) []byte, store db.Conn) (*Trie, error)
```

```
// Adds or update a sorted list of keys and their values to the SMT
// To delete, set the value to DefaultLeaf([]byte{0}).
func (s *Trie) Update(ctx context.Context, keys, values [][]byte) ([]byte, error) 
```
```
// commit changes to database
(s *Trie) Commit(ctx context.Context) error 
```
```
// LoadCache loads the first several layers of the merkle tree into memory. Depth is configured by "CacheHeightLimit"
// This is called after a SMT restarts so that it doesn't become slow with db reads
// LoadCache also updates the Root with the given root.
(s *Trie) LoadCache(ctx context.Context, root []byte) error 
```
```
// MerkleProofPast generates a Merkle proof of inclusion or non-inclusion
// for a given SMT root
// returns the audit path, bool (if key is included), key, value, error
// for PoP, key-value pair will be the key-value pair of queried key
// for PoA, key-value pair will be the key-value pair of leaf on the path of the non-included key
(s *Trie) MerkleProof(ctx context.Context, key, root []byte) ([][]byte, bool, []byte, []byte, error)
```
```
// VerifyInclusion verifies that key/value is included in the trie with latest root
VerifyInclusion(root []byte, auditPath [][]byte, key, value []byte) bool 
```
```
// VerifyInclusion verifies that key/value is included in the trie with latest root
// "key" is the non-included key
// "proofValue", "proofKey" is returned from MerkleProof()
VerifyNonInclusion(root []byte, ap [][]byte, key, proofValue, proofKey []byte) bool
```
## How to run?
The demo file is in the smsmt_demo folder.
You need to install MySQL, and MySQL should not require a password for the root user. If you encounter any isseus, this might help: https://stackoverflow.com/questions/3032054/how-to-remove-mysql-root-password

```
./tools/create_schema.sh(WARNING!!! make sure you don't have a db schema called "fpki", otherwise the existing "fpki" schema will be overwritten)
go run smt_demo/main.go
```







