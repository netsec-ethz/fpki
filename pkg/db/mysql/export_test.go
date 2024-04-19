package mysql

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type MysqlDBForTests struct {
	*mysqlDB
}

func NewMysqlDBForTests(db db.Conn) *MysqlDBForTests {
	return &MysqlDBForTests{
		mysqlDB: db.(*mysqlDB),
	}
}

func (c *MysqlDBForTests) DebugCheckCertsExist(ctx context.Context, ids []*common.SHA256Output,
	present []bool) error {

	return c.checkCertsExist(ctx, ids, present)
}

func (c *MysqlDBForTests) RetrieveDomainEntriesInDBJoin(
	ctx context.Context,
	start, end uint64,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDomainEntriesInDBJoin(ctx, start, end)
}

func (c *MysqlDBForTests) RetrieveDomainEntriesParallel(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDomainEntriesParallel(ctx, domainIDs)
}

func (c *MysqlDBForTests) RetrieveDomainEntriesSequential(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDomainEntriesSequential(ctx, domainIDs)
}

func RepeatStmt(elemCount int, dimensions int) string {
	return repeatStmt(elemCount, dimensions)
}
