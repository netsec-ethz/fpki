package mysql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

func (c *mysqlDB) LoadRoot(ctx context.Context) (*common.SHA256Output, error) {
	var key []byte
	if err := c.db.QueryRowContext(ctx, "SELECT key32 FROM root").Scan(&key); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error obtaining the root entry: %w", err)
	}
	return (*common.SHA256Output)(key), nil
}

func (c *mysqlDB) SaveRoot(ctx context.Context, root *common.SHA256Output) error {
	str := "REPLACE INTO root (key32) VALUES (?)"
	_, err := c.db.ExecContext(ctx, str, (*root)[:])
	if err != nil {
		return fmt.Errorf("error inserting root ID: %w", err)
	}
	return nil
}

func (c *mysqlDB) RetrieveTreeNode(ctx context.Context, key common.SHA256Output) ([]byte, error) {
	var value []byte
	str := "SELECT value FROM tree WHERE key32 = ?"
	err := c.db.QueryRowContext(ctx, str, key[:]).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("error retrieving node from tree: %w", err)
	}
	return value, nil
}

func (c *mysqlDB) DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error) {
	str := "DELETE FROM tree WHERE key32 IN " + repeatStmt(1, len(keys))
	params := make([]interface{}, len(keys))
	for i, k := range keys {
		params[i] = k[:]
	}
	res, err := c.db.ExecContext(ctx, str, params...)
	if err != nil {
		return 0, fmt.Errorf("error deleting keys from tree: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		panic(fmt.Errorf("unsupported retrieving number of rows affected: %w", err))
	}
	return int(n), nil
}

func (c *mysqlDB) UpdateTreeNodes(ctx context.Context, keyValuePairs []*db.KeyValuePair) (int, error) {
	if len(keyValuePairs) == 0 {
		return 0, nil
	}
	str := "REPLACE INTO tree (key32,value) VALUES " + repeatStmt(len(keyValuePairs), 2)
	params := make([]interface{}, 2*len(keyValuePairs))
	for i, pair := range keyValuePairs {
		params[i*2] = pair.Key[:]
		params[i*2+1] = pair.Value
	}
	res, err := c.db.ExecContext(ctx, str, params...)
	if err != nil {
		return 0, fmt.Errorf("error inserting key-values into tree: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		panic(fmt.Errorf("unsupported retrieving number of rows affected: %w", err))
	}
	return int(n), nil
}
