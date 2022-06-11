package updater

import (
	"context"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
)

type UpdaterTestAdapter MapUpdater

func NewMapTestUpdater(root []byte, cacheHeight int) (*UpdaterTestAdapter, error) {
	up, err := NewMapUpdater(root, cacheHeight)
	return (*UpdaterTestAdapter)(up), err
}

func (a *UpdaterTestAdapter) Conn() db.Conn {
	return (*MapUpdater)(a).dbConn
}

func (u *UpdaterTestAdapter) UpdateCerts(ctx context.Context, certs []*ctx509.Certificate) error {
	return (*MapUpdater)(u).updateCerts(ctx, certs)
}

func (u *UpdaterTestAdapter) UpdateDomainEntriesUsingCerts(ctx context.Context,
	certs []*ctx509.Certificate, readerNum int) (int, error) {

	return (*MapUpdater)(u).UpdateDomainEntriesUsingCerts(ctx, certs, readerNum)
}

func (a *UpdaterTestAdapter) FetchUpdatedDomainHash(ctx context.Context) (
	[]common.SHA256Output, error) {
	return (*MapUpdater)(a).fetchUpdatedDomainHash(ctx)
}

func (a *UpdaterTestAdapter) KeyValuePairToSMTInput(keyValuePair []db.KeyValuePair) (
	[][]byte, [][]byte, error) {

	return keyValuePairToSMTInput(keyValuePair)
}

func (a *UpdaterTestAdapter) SMT() *trie.Trie {
	return (*MapUpdater)(a).smt
}

func (a *UpdaterTestAdapter) SetSMT(smt *trie.Trie) {
	a.smt = smt
}

func (a *UpdaterTestAdapter) CommitChanges(ctx context.Context) error {
	return (*MapUpdater)(a).CommitSMTChanges(ctx)
}
