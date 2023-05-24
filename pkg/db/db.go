package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// KeyValuePair: key-value pair
type KeyValuePair struct {
	Key   common.SHA256Output
	Value []byte
}

type smt interface {
	LoadRoot(ctx context.Context) (*common.SHA256Output, error)
	SaveRoot(ctx context.Context, root *common.SHA256Output) error

	// RetrieveTreeNode: Retrieve one key-value pair from Tree table.
	RetrieveTreeNode(ctx context.Context, id common.SHA256Output) ([]byte, error)
	// UpdateTreeNodes: Update a list of key-value pairs in Tree table
	UpdateTreeNodes(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error)
	// DeleteTreeNodes: Delete a list of key-value pairs in Tree table
	DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error)
}

type dirty interface {

	// RetrieveDirtyDomains returns a channel of batches of updated domains.
	// A batch will have a implementation dependent size.
	// Each updated domain represents the SHA256 of the textual domain that was updated and
	// present in the `updates` table.
	RetrieveDirtyDomains(ctx context.Context) ([]*common.SHA256Output, error)

	// ReplaceDirtyDomainPayloads retrieves dirty domains from the dirty list, starting
	// at firstRow and finishing at lastRow (for a total of lastRow - firstRow + 1 domains),
	// computes the aggregated payload for their certificates and policies, and stores it in the DB.
	// The aggregated payload takes into account all policies and certificates needed for that
	// domain, including e.g. the trust chain.
	ReplaceDirtyDomainPayloads(ctx context.Context, firstRow, lastRow int) error

	//DirtyDomainsCount returns the number of domains that are still to be updated.
	DirtyDomainsCount(ctx context.Context) (int, error)

	CleanupDirty(ctx context.Context) error
}

type certs interface {

	// CheckCertsExist returns a slice of true/false values. Each value indicates if
	// the corresponding certificate identified by its ID is already present in the DB.
	CheckCertsExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error)

	InsertCerts(ctx context.Context, ids, parents []*common.SHA256Output, expirations []*time.Time,
		payloads [][]byte) error

	// UpdateDomainCerts updates the domain_certs table with new entries.
	UpdateDomainCerts(ctx context.Context, domainIDs, certIDs []*common.SHA256Output) error

	// RetrieveDomainCertificatesPayload retrieves the domain's certificate payload ID and the payload
	// itself, given the domain ID.
	RetrieveDomainCertificatesPayload(ctx context.Context, id common.SHA256Output) (
		certIDsID *common.SHA256Output, certIDs []byte, err error)
}

type policies interface {
	// CheckPoliciesExist returns a slice of true/false values. Each value indicates if
	// the corresponding policy identified by its ID is already present in the DB.
	CheckPoliciesExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error)

	InsertPolicies(ctx context.Context, ids, parents []*common.SHA256Output,
		expirations []*time.Time, payloads [][]byte) error

	// UpdateDomainPolicies updates the domain_policies table with new entries.
	UpdateDomainPolicies(ctx context.Context, domainIDs, policyIDs []*common.SHA256Output) error

	// RetrieveDomainPoliciesPayload returns the policy related payload for a given domain.
	// This includes the RPCs, SPs, etc.
	RetrieveDomainPoliciesPayload(ctx context.Context, id common.SHA256Output) (
		payloadID *common.SHA256Output, payload []byte, err error)
}

type Conn interface {
	smt
	dirty
	certs
	policies

	// TODO(juagargi) remove the temporary access to the sql.DB object
	DB() *sql.DB
	// Close closes the connection.
	Close() error

	// TruncateAllTables resets the DB to an initial state.
	TruncateAllTables(ctx context.Context) error

	// UpdateDomains updates the domains and dirty tables.
	UpdateDomains(ctx context.Context, domainIDs []*common.SHA256Output, domainNames []string) error

	// RetrieveDomainEntries: Retrieve a list of domain entries table
	RetrieveDomainEntries(ctx context.Context, id []*common.SHA256Output) ([]*KeyValuePair, error)
}
