package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
)

// TreeNodeRecord stores one serialized SMT node as persisted in the tree table.
// Key is the hash of the SMT node; Value is the serialized trie batch.
type TreeNodeRecord struct {
	Key   common.SHA256Output
	Value []byte
}

// DomainEntryRecord stores one domain entry as consumed by the SMT updater.
// DomainID is SHA256(domain name); Payload is the byte representation from
// which the SMT leaf value is derived.
type DomainEntryRecord struct {
	DomainID common.SHA256Output
	Payload  []byte
}

// DirtyDomainEntriesCursor tracks per-partition progress while retrieving dirty-domain
// entries in bounded bundles.
type DirtyDomainEntriesCursor struct {
	PartitionOffsets   []uint64
	PartitionExhausted []bool
	NextPartition      int
}

type smt interface {
	LoadRoot(ctx context.Context) (*common.SHA256Output, error)
	SaveRoot(ctx context.Context, root *common.SHA256Output) error

	// RetrieveTreeNode retrieves one serialized SMT node from the tree table.
	RetrieveTreeNode(ctx context.Context, id common.SHA256Output) ([]byte, error)
	// UpdateTreeNodes updates a list of SMT node records in the tree table.
	UpdateTreeNodes(ctx context.Context, keyValuePairs []*TreeNodeRecord) (int, error)
	// DeleteTreeNodes deletes a list of SMT node rows from the tree table.
	DeleteTreeNodes(ctx context.Context, keys []common.SHA256Output) (int, error)
}

type dirty interface {
	DirtyCount(ctx context.Context) (uint64, error)

	// RetrieveDirtyDomains returns a channel of batches of updated domains.
	// A batch will have a implementation dependent size.
	// Each updated domain represents the SHA256 of the textual domain that was updated and
	// present in the `updates` table.
	RetrieveDirtyDomains(ctx context.Context) ([]common.SHA256Output, error)

	// InsertDomainsIntoDirty adds the domain IDs into the dirty table, to signal that these
	// domains have not been fully processed yet.
	InsertDomainsIntoDirty(ctx context.Context, ids []common.SHA256Output) error

	// InsertCsvIntoDirty inserts all the domain IDs in the CSV file into the dirty table.
	InsertCsvIntoDirty(ctx context.Context, filename string) error

	// RecomputeDirtyDomainsCertAndPolicyIDs recomputes the aggregated certificate and policy
	// payload identifiers for all dirty domains and stores them in the DB. The aggregated payload
	// takes into account all policies and certificates needed for that domain, including e.g. the
	// trust chain.
	RecomputeDirtyDomainsCertAndPolicyIDs(ctx context.Context) error

	// CleanupDirty removes all entries from the dirty table.
	CleanupDirty(ctx context.Context) error
}

type certs interface {

	// InsertCsvIntoCerts inserts all the certificate fields into the certs table.
	InsertCsvIntoCerts(ctx context.Context, filename string) error

	// InsertCsvIntoDomainCerts inserts all the certificate-domain records into the domain_certs
	// table.
	InsertCsvIntoDomainCerts(ctx context.Context, filename string) error

	// CheckCertsExist returns a slice of true/false values. Each value indicates if
	// the corresponding certificate identified by its ID is already present in the DB.
	CheckCertsExist(ctx context.Context, ids []common.SHA256Output) ([]bool, error)

	UpdateCerts(
		ctx context.Context,
		ids []common.SHA256Output,
		parents []*common.SHA256Output,
		expirations []time.Time,
		payloads [][]byte,
	) error

	// UpdateDomainCerts updates the domain_certs table with new entries.
	UpdateDomainCerts(ctx context.Context, domainIDs, certIDs []common.SHA256Output) error

	// RetrieveDomainCertificatesIDs retrieves the domain's certificate payload ID and the payload
	// itself, given the domain ID.
	RetrieveDomainCertificatesIDs(ctx context.Context, id common.SHA256Output,
	) (certIDsID common.SHA256Output, certIDs []byte, err error)

	// RetrieveCertificatePayloads returns the payload for each of the certificates identified
	// by the passed ID.
	RetrieveCertificatePayloads(ctx context.Context, IDs []common.SHA256Output) ([][]byte, error)

	// LastCTlogServerState returns the last state of the CT log server written into the DB.
	// The url specifies the CT log server from which this data comes from.
	LastCTlogServerState(ctx context.Context, url string) (size int64, sth []byte, err error)

	// UpdateLastCTlogServerState updates the last status of the CT log server written into the DB.
	// The url specifies the CT log server from which this data comes from.
	UpdateLastCTlogServerState(ctx context.Context, url string, size int64, sth []byte) error

	// PruneCerts removes all certificates that are no longer valid according to the paramter.
	// I.e. any certificate whose NotAfter date is equal or before the parameter.
	PruneCerts(ctx context.Context, now time.Time) error
}

type policies interface {
	// CheckPoliciesExist returns a slice of true/false values. Each value indicates if
	// the corresponding policy identified by its ID is already present in the DB.
	CheckPoliciesExist(ctx context.Context, ids []common.SHA256Output) ([]bool, error)

	UpdatePolicies(
		ctx context.Context,
		ids []common.SHA256Output,
		parents []*common.SHA256Output,
		expirations []time.Time, payloads [][]byte) error

	// UpdateDomainPolicies updates the domain_policies table with new entries.
	UpdateDomainPolicies(ctx context.Context, domainIDs, policyIDs []common.SHA256Output) error

	// RetrieveDomainPoliciesIDs returns the policy related payload for a given domain.
	// This includes the RPCs, SPs, etc.
	RetrieveDomainPoliciesIDs(ctx context.Context, id common.SHA256Output) (
		payloadID common.SHA256Output, payload []byte, err error)

	// RetrievePolicyPayloads returns the payload for each of the policies identified
	// by the passed ID.
	RetrievePolicyPayloads(ctx context.Context, IDs []common.SHA256Output) ([][]byte, error)
}

type certsAndPolicies interface {
	// RetrieveCertificateOrPolicyPayloads returns the payloads for each identifier regardless whether it is a certificate or a policy
	RetrieveCertificateOrPolicyPayloads(ctx context.Context, IDs []common.SHA256Output) ([][]byte, error)
}

// Conn is a connection to operate with the DB.
type Conn interface {
	smt
	dirty
	certs
	policies
	certsAndPolicies

	// TODO(juagargi) remove the temporary access to the sql.DB object
	DB() *sql.DB
	// Close closes the connection.
	Close() error

	// TruncateAllTables resets the DB to an initial state.
	TruncateAllTables(ctx context.Context) error

	// InsertCsvIntoDomains inserts all the domains in the CSV into the domains table.
	InsertCsvIntoDomains(ctx context.Context, filename string) error

	// UpdateDomains updates the domains table.
	UpdateDomains(
		ctx context.Context,
		domainIDs []common.SHA256Output,
		domainNames []string,
	) error

	// RetrieveDomainEntries retrieves domain-entry payloads for the specified domain IDs.
	RetrieveDomainEntries(
		ctx context.Context,
		ids []common.SHA256Output,
	) ([]DomainEntryRecord, error)

	// RetrieveDomainEntriesDirtyOnes returns a list of key-values whose domain IDs are specified
	// by the dirty table entries starting from `start` and not including `end`.
	RetrieveDomainEntriesDirtyOnes(ctx context.Context, start, end uint64) ([]DomainEntryRecord, error)

	// RetrieveDomainEntriesDirtyBundle retrieves up to maxBundleSize dirty-domain entries using
	// partition-local progress tracked in cursor. The returned cursor must be passed to the next
	// call. done reports whether all partitions have been fully consumed.
	RetrieveDomainEntriesDirtyBundle(
		ctx context.Context,
		cursor *DirtyDomainEntriesCursor,
		maxBundleSize uint64,
	) ([]DomainEntryRecord, *DirtyDomainEntriesCursor, bool, error)
}
