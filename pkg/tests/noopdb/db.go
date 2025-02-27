package noopdb

import (
	"context"
	"database/sql"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
)

type Conn struct{}

var _ db.Conn = (*Conn)(nil)

func (*Conn) DB() *sql.DB {
	return nil
}

func (*Conn) Close() error {
	return nil
}

func (*Conn) TruncateAllTables(context.Context) error {
	return nil
}

func (*Conn) InsertCsvIntoCerts(context.Context, string) error {
	return nil
}

func (*Conn) InsertCsvIntoDirty(context.Context, string) error {
	return nil
}

func (*Conn) InsertCsvIntoDomains(context.Context, string) error {
	return nil
}

func (*Conn) InsertCsvIntoDomainCerts(context.Context, string) error {
	return nil
}

func (*Conn) UpdateDomains(context.Context, []common.SHA256Output, []string) error {
	return nil
}

func (*Conn) RetrieveDomainEntries(context.Context, []common.SHA256Output) ([]db.KeyValuePair, error) {
	return nil, nil
}

func (*Conn) RetrieveDomainEntriesDirtyOnes(context.Context, uint64, uint64) ([]db.KeyValuePair, error) {
	return nil, nil
}

func (*Conn) LoadRoot(context.Context) (*common.SHA256Output, error) {
	return nil, nil
}
func (*Conn) SaveRoot(context.Context, *common.SHA256Output) error {
	return nil
}

func (*Conn) RetrieveTreeNode(context.Context, common.SHA256Output) ([]byte, error) {
	return nil, nil
}
func (*Conn) UpdateTreeNodes(context.Context, []*db.KeyValuePair) (int, error) {
	return 0, nil
}
func (*Conn) DeleteTreeNodes(context.Context, []common.SHA256Output) (int, error) {
	return 0, nil
}

func (*Conn) DirtyCount(context.Context) (uint64, error) {
	return 0, nil
}

func (*Conn) RetrieveDirtyDomains(context.Context) ([]common.SHA256Output, error) {
	return nil, nil
}

func (*Conn) InsertDomainsIntoDirty(context.Context, []common.SHA256Output) error {
	return nil
}

func (*Conn) RecomputeDirtyDomainsCertAndPolicyIDs(context.Context) error {
	return nil
}

func (*Conn) CleanupDirty(context.Context) error {
	return nil
}

func (*Conn) CheckCertsExist(context.Context, []common.SHA256Output) ([]bool, error) {
	return nil, nil
}

func (*Conn) UpdateCerts(context.Context, []common.SHA256Output, []*common.SHA256Output, []time.Time, [][]byte) error {
	return nil
}

func (*Conn) UpdateDomainCerts(context.Context, []common.SHA256Output, []common.SHA256Output) error {
	return nil
}

func (*Conn) RetrieveDomainCertificatesIDs(context.Context, common.SHA256Output) (common.SHA256Output, []byte, error) {
	return common.SHA256Output{}, nil, nil
}

func (*Conn) RetrieveCertificatePayloads(context.Context, []common.SHA256Output) ([][]byte, error) {
	return nil, nil
}

func (*Conn) LastCTlogServerState(context.Context, string) (int64, []byte, error) {
	return 0, nil, nil
}

func (*Conn) UpdateLastCTlogServerState(context.Context, string, int64, []byte) error {
	return nil
}

func (*Conn) PruneCerts(context.Context, time.Time) error {
	return nil
}

func (*Conn) CheckPoliciesExist(context.Context, []common.SHA256Output) ([]bool, error) {
	return nil, nil
}

func (*Conn) UpdatePolicies(context.Context, []common.SHA256Output, []*common.SHA256Output, []time.Time, [][]byte) error {
	return nil
}

func (*Conn) UpdateDomainPolicies(context.Context, []common.SHA256Output, []common.SHA256Output) error {
	return nil
}

func (*Conn) RetrieveDomainPoliciesIDs(context.Context, common.SHA256Output) (common.SHA256Output, []byte, error) {
	return common.SHA256Output{}, nil, nil
}

func (*Conn) RetrievePolicyPayloads(context.Context, []common.SHA256Output) ([][]byte, error) {
	return nil, nil
}

func (*Conn) RetrieveCertificateOrPolicyPayloads(context.Context, []common.SHA256Output) ([][]byte, error) {
	return nil, nil
}
