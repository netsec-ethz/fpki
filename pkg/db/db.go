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

// Conn: interface for db connection
type Conn interface {
	// TODO(juagargi) remove the temporary access to the sql.DB object
	DB() *sql.DB
	// Close closes the connection.
	Close() error

	// TruncateAllTables resets the DB to an initial state.
	TruncateAllTables(ctx context.Context) error

	LoadRoot(ctx context.Context) (*common.SHA256Output, error)
	SaveRoot(ctx context.Context, root *common.SHA256Output) error

	// ReplaceDirtyDomainPayloads retrieves dirty domains from the dirty list, starting
	// at firstRow and finishing at lastRow (for a total of lastRow - firstRow + 1 domains),
	// computes the aggregated payload for their certificates and policies, and stores it in the DB.
	// The aggregated payload takes into account all policies and certificates needed for that
	// domain, including e.g. the trust chain.
	ReplaceDirtyDomainPayloads(ctx context.Context, firstRow, lastRow int) error

	// RetrieveDomainCertificatesPayload retrieves the domain's certificate payload ID and the payload
	// itself, given the domain ID.
	RetrieveDomainCertificatesPayload(ctx context.Context, id common.SHA256Output) (
		certIDsID *common.SHA256Output, certIDs []byte, err error)

	// RetrieveDomainPoliciesPayload returns the policy related payload for a given domain.
	// This includes the RPCs, SPs, etc.
	RetrieveDomainPoliciesPayload(ctx context.Context, id common.SHA256Output) (
		payloadID *common.SHA256Output, payload []byte, err error)

	// CheckCertsExist returns a slice of true/false values. Each value indicates if
	// the corresponding certificate identified by its ID is already present in the DB.
	CheckCertsExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error)

	// CheckPoliciesExist returns a slice of true/false values. Each value indicates if
	// the corresponding policy identified by its ID is already present in the DB.
	CheckPoliciesExist(ctx context.Context, ids []*common.SHA256Output) ([]bool, error)

	//////////////////////////////////////////////////////////////////
	// check if the functions below are needed after the new design //
	//////////////////////////////////////////////////////////////////

	InsertCerts(ctx context.Context, ids, parents []*common.SHA256Output, expirations []*time.Time,
		payloads [][]byte) error

	// UpdateDomainsWithCerts updates the domains and dirty tables with entries that are
	// _probably_ not present there.
	UpdateDomainsWithCerts(ctx context.Context, certIDs, domainIDs []*common.SHA256Output,
		domainNames []string) error

	// ************************************************************
	//              Function for Tree table
	// ************************************************************

	// RetrieveTreeNode: Retrieve one key-value pair from Tree table.
	RetrieveTreeNode(ctx context.Context, id common.SHA256Output) ([]byte, error)

	// UpdateTreeNodes: Update a list of key-value pairs in Tree table
	UpdateTreeNodes(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error)

	// DeleteTreeNodes: Delete a list of key-value pairs in Tree table
	DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error)

	// ************************************************************
	//             Function for DomainEntries table
	// ************************************************************

	// RetrieveDomainEntries: Retrieve a list of domain entries table
	RetrieveDomainEntries(ctx context.Context, id []*common.SHA256Output) ([]*KeyValuePair, error)

	// UpdateDomainEntries: Update a list of key-value pairs in domain entries table
	UpdateDomainEntries(ctx context.Context, keyValuePairs []*KeyValuePair) (int, error)

	// ************************************************************
	//           Function for Updates table
	// ************************************************************

	// CountUpdatedDomains: Retrieve number of updated domains during this updates.
	CountUpdatedDomains(ctx context.Context) (int, error) // TODO(juagargi) review usage

	// AddUpdatedDomains: Add a list of hashes of updated domain into the updates table. If key exists, ignore it.
	AddUpdatedDomains(ctx context.Context, keys []common.SHA256Output) (int, error)

	// TODO(yongzhe): investigate whether perQueryLimit is necessary
	// RetrieveUpdatedDomains: Retrieve all updated domain hashes from update table
	RetrieveUpdatedDomains(ctx context.Context, perQueryLimit int) ([]common.SHA256Output, error)

	// RemoveAllUpdatedDomains: Truncate updates table; Called after updating is finished
	RemoveAllUpdatedDomains(ctx context.Context) error

	// UpdatedDomains returns a channel of batches of updated domains.
	// A batch will have a implementation dependent size.
	// Each updated domain represents the SHA256 of the textual domain that was updated and
	// present in the `updates` table.
	UpdatedDomains(ctx context.Context) ([]*common.SHA256Output, error)

	//DirtyDomainsCount returns the number of domains that are still to be updated.
	DirtyDomainsCount(ctx context.Context) (int, error)
	CleanupDirty(ctx context.Context) error
}
