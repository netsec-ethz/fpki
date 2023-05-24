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
