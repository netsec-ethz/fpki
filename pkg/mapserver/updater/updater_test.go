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
	"github.com/netsec-ethz/fpki/pkg/mapserver/logpicker"
	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateCerts: test updateCerts()
func TestUpdateCerts(t *testing.T) {
	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, newMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := newMockDB()
	updater, err := getMockUpdater(parser, smt, updaterDB)
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
	err = updater.updateCerts(ctx, certs)
	require.NoError(t, err)

	// update table should be empty
	assert.Equal(t, 0, len(updaterDB.updatesTable))

	// check whether certs are correctly added to the db
	for _, cert := range certs {
		domains := parser.ExtractAffectedDomains(extractCertDomains(cert))

		for _, domain := range domains {
			domainHash := projectCommon.SHA256Hash32Bytes([]byte(domain))
			assert.Contains(t, updaterDB.domainEntriesTable, domainHash)
			domainEntryBytes := updaterDB.domainEntriesTable[domainHash]

			domainEntry, err := common.DeserializeDomainEntry(domainEntryBytes)
			require.NoError(t, err)

			for _, caList := range domainEntry.CAEntry {
				if caList.CAName != cert.Issuer.CommonName {
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

	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, newMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := newMockDB()
	updater, err := getMockUpdater(parser, smt, updaterDB)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err = updater.updateRPCAndPC(ctx, pcList, rpcList)
	require.NoError(t, err)

	// check pc list in memory
	for _, pc := range pcList {
		domainHash := projectCommon.SHA256Hash32Bytes([]byte(pc.Subject))
		assert.Contains(t, updaterDB.domainEntriesTable, domainHash)
		domainEntryBytes := updaterDB.domainEntriesTable[domainHash]

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
		assert.Contains(t, updaterDB.domainEntriesTable, domainHash)
		domainEntryBytes := updaterDB.domainEntriesTable[domainHash]

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
	parser, err := domain.NewDomainParser()
	require.NoError(t, err)

	smt, err := trie.NewTrie(nil, projectCommon.SHA256Hash, newMockDB())
	require.NoError(t, err)
	smt.CacheHeightLimit = 233

	updaterDB := newMockDB()
	updater, err := getMockUpdater(parser, smt, updaterDB)
	require.NoError(t, err)

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	randomKeys := []projectCommon.SHA256Output{}
	for i := 0; i < 15; i++ {
		newRandomKey := getRandomHash()
		updaterDB.updatesTable[newRandomKey] = empty
		randomKeys = append(randomKeys, newRandomKey)
	}

	// result is not important.
	_, err = updater.fetchUpdatedDomainHash(ctx)

	// make sure the db is cleaned.
	assert.Equal(t, 0, len(updaterDB.updatesTable))
}

func getRandomHash() projectCommon.SHA256Output {
	return projectCommon.SHA256Hash32Bytes(generateRandomBytes(50))
}

// get a updater using mock db
func getMockUpdater(parser *domain.DomainParser, smt *trie.Trie, updaterDB *MockDB) (*MapUpdater, error) {
	return &MapUpdater{
		domainParser: parser,
		smt:          smt,
		dbConn:       updaterDB,
	}, nil
}
