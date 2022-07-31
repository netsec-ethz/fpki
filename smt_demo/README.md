# SMT Demo
This is a demo for the efficient and database-supported SMT implementation.

The key and value stored in the SMT should be 32 bytes(you can use SHA256). Before using the SMT library, you should hash the key and values, and sort the key-value pairs by hashed keys from low to high, before adding the pairs into SMT(more details on the demo). One pair should be (32bytes, 32bytes), and the order should be (000, XXX), (001, XXX), (100, XXX), (111, XXX)

You can use Update() to update one batch of key-value pairs. Commit() is optional if you don't want to store the SMT permanently. 

If you want to persist the SMT, you need:
1. Commit() after every changes (after Update(){}). All changes after Commit() will not be stored in the database but memory. If the program crashes, the uncommitted changes will be lost.
2. Store the Tree Head before terminating the program. You need the Tree Head to reload the SMT

If you only want to run SMT in memory, Commit() is not useful.

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
// SMT lib has some internal lists to record the changes to the database. So no parameter is needed. You just need to call commit() once you want to persist the changes.
// Call Commit() before terminating, or periodically commit the changes, to avoid data loss and memory exhaustion.
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
// VerifyInclusion verifies that key/value is included in the SMT with latest root
VerifyInclusion(root []byte, auditPath [][]byte, key, value []byte) bool 
```
```
// VerifyInclusion verifies that key/value is included in the SMT with latest root
// "key" is the non-included key
// "proofValue", "proofKey" is returned from MerkleProof()
VerifyNonInclusion(root []byte, ap [][]byte, key, proofValue, proofKey []byte) bool
```
## How to run?
You need to install MySQL, and MySQL should not require a password for the root user. If you encounter password isseus, this might help: https://stackoverflow.com/questions/3032054/how-to-remove-mysql-root-password

```
cd ..
./tools/create_schema.sh (WARNING!!! make sure you don't have a db schema called "fpki", otherwise the existing "fpki" schema will be overwritten)
go run smt_demo/main.go
```