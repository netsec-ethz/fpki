package db

import "context"

// FullID: Key for flatten tree investigation
type FullID [33]byte // first byte is depth -1 (root not allowed)

// RetrieveValue returns the value associated with the node.
func (c *mysqlDB) RetrieveValue(ctx context.Context, id FullID) ([]byte, error) {
	var val []byte
	row := c.prepGetValue.QueryRowContext(ctx, id[:])
	if err := row.Scan(&val); err != nil {
		return nil, err
	}
	return val, nil
}

// RetrieveNode returns the value and the proof path (without the root) for a given node.
// Since each one of the steps of the proof path has a fixed size, returning the path
// as a slice is sufficient to know how many steps there were in the proof path.
func (c *mysqlDB) RetrieveNode(ctx context.Context, id FullID) ([]byte, []byte, error) {
	var val, proofPath []byte
	row := c.prepValueProofPath.QueryRowContext(ctx, id[:])
	if err := row.Scan(&val, &proofPath); err != nil {
		return nil, nil, err
	}
	return val, proofPath, nil
}
