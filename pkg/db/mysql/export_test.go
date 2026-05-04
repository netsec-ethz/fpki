package mysql

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type MysqlDBForTests struct {
	*mysqlDB
}

// NewMysqlDBForTests exposes mysqlDB internals to package tests.
func NewMysqlDBForTests(db db.Conn) *MysqlDBForTests {
	return &MysqlDBForTests{
		mysqlDB: db.(*mysqlDB),
	}
}

func (c *MysqlDBForTests) DebugCheckCertsExist(ctx context.Context, ids []common.SHA256Output,
	present []bool) error {

	return c.checkCertsExist(ctx, ids, present)
}

func (c *MysqlDBForTests) RetrieveDirtyDomainEntriesParallel(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) ([]db.DomainEntryRecord, error) {

	return c.retrieveDirtyDomainEntriesParallel(ctx, domainIDs)
}

func (c *MysqlDBForTests) RetrieveDirtyDomainEntriesSequential(
	ctx context.Context,
	domainIDs []common.SHA256Output,
) ([]db.DomainEntryRecord, error) {

	return c.retrieveDirtyDomainEntriesSequential(ctx, domainIDs)
}

func RepeatStmt(elemCount int, dimensions int) string {
	return repeatStmt(elemCount, dimensions)
}

func CallCalcDirtyDomainsForTests(
	ctx context.Context,
	conn db.Conn,
	partition int,
	chunkSize int,
) (int64, error) {
	sqlConn, err := conn.DB().Conn(ctx)
	if err != nil {
		return 0, fmt.Errorf("creating SQL connection for test: %w", err)
	}
	defer sqlConn.Close()

	return callCalcDirtyDomains(ctx, sqlConn, partition, chunkSize)
}
