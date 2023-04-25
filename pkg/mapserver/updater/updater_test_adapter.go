package updater

import (
	"context"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

type UpdaterTestAdapter MapUpdater

func NewMapTestUpdater(config *db.Configuration, root []byte, cacheHeight int) (*UpdaterTestAdapter, error) {
	up, err := NewMapUpdater(config, root, cacheHeight)
	return (*UpdaterTestAdapter)(up), err
}

func (a *UpdaterTestAdapter) Conn() db.Conn {
	return (*MapUpdater)(a).dbConn
}

func (u *UpdaterTestAdapter) UpdateCerts(ctx context.Context, certs []*ctx509.Certificate, certChains [][]*ctx509.Certificate) error {
	return (*MapUpdater)(u).updateCerts(ctx, certs, certChains)
}

func (u *UpdaterTestAdapter) UpdateDomainEntriesUsingCerts(ctx context.Context,
	certs []*ctx509.Certificate, certChains [][]*ctx509.Certificate, readerNum int) ([]*db.KeyValuePair, int, error) {

	return (*MapUpdater)(u).DeletemeUpdateDomainEntriesTableUsingCerts(ctx, certs, certChains)
}

func (a *UpdaterTestAdapter) FetchUpdatedDomainHash(ctx context.Context) (
	[]common.SHA256Output, error) {
	return (*MapUpdater)(a).fetchUpdatedDomainHash(ctx)
}

func (a *UpdaterTestAdapter) KeyValuePairToSMTInput(keyValuePair []*db.KeyValuePair) (
	[][]byte, [][]byte, error) {

	return keyValuePairToSMTInput(keyValuePair)
}

func (a *UpdaterTestAdapter) SMT() *trie.Trie {
	return (*MapUpdater)(a).smt
}

func (a *UpdaterTestAdapter) SetSMT(smt *trie.Trie) {
	a.smt = smt
}

func (a *UpdaterTestAdapter) SetDBConn(dbConn db.Conn) {
	a.dbConn = dbConn
}

func (a *UpdaterTestAdapter) GetRoot() []byte {
	return (*MapUpdater)(a).GetRoot()
}

func (a *UpdaterTestAdapter) Close() error {
	return (*MapUpdater)(a).Close()
}

func (a *UpdaterTestAdapter) CommitSMTChanges(ctx context.Context) error {
	return (*MapUpdater)(a).CommitSMTChanges(ctx)
}
