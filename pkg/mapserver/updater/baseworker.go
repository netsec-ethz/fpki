package updater

import (
	"github.com/netsec-ethz/fpki/pkg/db"
)

type baseWorker struct {
	Id      int
	Manager *Manager
	Conn    db.Conn
}

func newBaseWorker(id int, m *Manager, conn db.Conn) *baseWorker {
	return &baseWorker{
		Id:      id,
		Manager: m,
		Conn:    conn,
	}
}
