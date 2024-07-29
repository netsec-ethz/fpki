package updater

import (
	"context"

	"github.com/netsec-ethz/fpki/pkg/db"
)

type baseWorker struct {
	Id      int
	Ctx     context.Context
	Manager *Manager
	Conn    db.Conn
}

func newBaseWorker(ctx context.Context, id int, m *Manager, conn db.Conn) *baseWorker {
	return &baseWorker{
		Id:      id,
		Ctx:     ctx,
		Manager: m,
		Conn:    conn,
	}
}
