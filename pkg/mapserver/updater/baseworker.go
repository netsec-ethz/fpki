package updater

import (
	"github.com/netsec-ethz/fpki/pkg/db"
)

type baseWorker struct {
	Manager *Manager
	Conn    db.Conn
}

func newBaseWorker(m *Manager, conn db.Conn) *baseWorker {
	return &baseWorker{
		Manager: m,
		Conn:    conn,
	}
}
