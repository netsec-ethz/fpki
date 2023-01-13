package updater

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/x509"
	projectCommon "github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/domain"
	"github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/internal"
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateCerts: test updateCerts()
func TestUpdateCerts(t *testing.T) {
	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, internal.NewMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := internal.NewMockDB()
	updater, err := getMockUpdater(smt, updaterDB)
	require.NoError(t, err)

	certs := []*x509.Certificate{}

	// load test certs
	files, err := ioutil.ReadDir("./testdata/certs/")
	require.NoError(t, err, "ioutil.ReadDir")
	for _, file := range files {
		cert, err := projectCommon.CTX509CertFromFile("./testdata/certs/" + file.Name())
		require.NoError(t, err, "projectCommon.CTX509CertFromFile")
		certs = append(certs, cert)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// update the db using the certs
	emptyCertChains := make([][]*x509.Certificate, len(certs))
	err = updater.updateCerts(ctx, certs, emptyCertChains)
	require.NoError(t, err)

	// update table should be empty
	assert.Equal(t, 0, len(updaterDB.UpdatesTable))

	// check whether certs are correctly added to the db
	for _, cert := range certs {
		domains := domain.ExtractAffectedDomains(extractCertDomains(cert))

		for _, domain := range domains {
			domainHash := projectCommon.SHA256Hash32Bytes([]byte(domain))
			assert.Contains(t, updaterDB.DomainEntriesTable, domainHash)
			domainEntryBytes := updaterDB.DomainEntriesTable[domainHash]

			domainEntry, err := common.DeserializeDomainEntry(domainEntryBytes)
			require.NoError(t, err)

			for _, caList := range domainEntry.CAEntry {
				if caList.CAName != cert.Issuer.String() {
					assert.NotContains(t, caList.DomainCerts, cert.Raw)
				} else {
					assert.Contains(t, caList.DomainCerts, cert.Raw)
				}
			}

			// test if SMT response is correct
			_, isPoP, _, _, err := smt.MerkleProof(ctx, domainHash[:])
			assert.True(t, isPoP)
			require.NoError(t, err)
		}
	}
}

// TestUpdateRPCAndPC: test updateRPCAndPC()
func TestUpdateRPCAndPC(t *testing.T) {
	pcList, rpcList, err := logpicker.GetPCAndRPC("./testdata/domain_list/domains.txt", 0, 0, 20)
	require.NoError(t, err)

	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, internal.NewMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := internal.NewMockDB()
	updater, err := getMockUpdater(smt, updaterDB)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err = updater.updateRPCAndPC(ctx, pcList, rpcList)
	require.NoError(t, err)

	// check pc list in memory
	for _, pc := range pcList {
		domainHash := projectCommon.SHA256Hash32Bytes([]byte(pc.Subject))
		assert.Contains(t, updaterDB.DomainEntriesTable, domainHash)
		domainEntryBytes := updaterDB.DomainEntriesTable[domainHash]

		domainEntry, err := common.DeserializeDomainEntry(domainEntryBytes)
		require.NoError(t, err)

		for _, caList := range domainEntry.CAEntry {
			if caList.CAName != pc.CAName {
				assert.Equal(t, pc, caList.CurrentPC)
			} else {
				assert.NotEqual(t, pc, caList.CurrentPC)
			}
		}

		// test if SMT response is correct
		_, isPoP, _, _, err := smt.MerkleProof(ctx, domainHash[:])
		assert.True(t, isPoP)
		require.NoError(t, err)
	}

	// check rpc list in memory
	for _, rpc := range rpcList {
		domainHash := projectCommon.SHA256Hash32Bytes([]byte(rpc.Subject))
		assert.Contains(t, updaterDB.DomainEntriesTable, domainHash)
		domainEntryBytes := updaterDB.DomainEntriesTable[domainHash]

		domainEntry, err := common.DeserializeDomainEntry(domainEntryBytes)
		require.NoError(t, err)

		for _, caList := range domainEntry.CAEntry {
			if caList.CAName != rpc.CAName {
				assert.Equal(t, rpc, caList.CurrentRPC)
			} else {
				assert.NotEqual(t, rpc, caList.CurrentRPC)
			}
		}

		// test if SMT response is correct
		_, isPoP, _, _, err := smt.MerkleProof(ctx, domainHash[:])
		assert.True(t, isPoP)
		require.NoError(t, err)
	}
}

// TestFetchUpdatedDomainHash: test fetchUpdatedDomainHash()
func TestFetchUpdatedDomainHash(t *testing.T) {
	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, internal.NewMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := internal.NewMockDB()
	updater, err := getMockUpdater(smt, updaterDB)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	randomKeys := []projectCommon.SHA256Output{}
	for i := 0; i < 15; i++ {
		newRandomKey := getRandomHash()
		updaterDB.UpdatesTable[newRandomKey] = struct{}{}
		randomKeys = append(randomKeys, newRandomKey)
	}

	// result is not important.
	_, err = updater.fetchUpdatedDomainHash(ctx)
	require.NoError(t, err)

	// make sure the db is cleaned.
	assert.Equal(t, 0, len(updaterDB.UpdatesTable))
}

func getRandomHash() projectCommon.SHA256Output {
	return projectCommon.SHA256Hash32Bytes(generateRandomBytes(50))
}

// get a updater using mock db
func getMockUpdater(smt *trie.Trie, updaterDB *internal.MockDB) (*MapUpdater, error) {
	return &MapUpdater{
		smt:    smt,
		dbConn: updaterDB,
	}, nil
}
