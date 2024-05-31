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

func (c *MysqlDBForTests) RetrieveDirtyDomainEntriesInDBJoin(
	ctx context.Context,
	start, end uint64,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDirtyDomainEntriesInDBJoin(ctx, start, end)
}

func (c *MysqlDBForTests) RetrieveDirtyDomainEntriesParallel(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDirtyDomainEntriesParallel(ctx, domainIDs)
}

func (c *MysqlDBForTests) RetrieveDirtyDomainEntriesSequential(
	ctx context.Context,
	domainIDs []*common.SHA256Output,
) ([]*db.KeyValuePair, error) {

	return c.retrieveDirtyDomainEntriesSequential(ctx, domainIDs)
}

func RepeatStmt(elemCount int, dimensions int) string {
	return repeatStmt(elemCount, dimensions)
}
