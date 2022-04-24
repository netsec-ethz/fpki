This is a DB-based sparse merkle tree. Use mysql to store the nodes, and "https://github.com/celestiaorg/smt" to construct the sparse merkle tree.


Some performance report:

Generate proof: 8us
Update 3000 leaves: 52ms in total
Load SMT from DB: 18ms in total
Save SMT to DB: 3.3s in total

The performace of saving is not good. However, this can be improved using multi-threading or optimizing the DB setup. Currently I only use the default setup and single thread.