package updater_test

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db/mock_db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestMinimalAllocsCertWorker checks that the calls to deduplicate elements in CertWorker
// do not need special memory allocations, due to the static fields present in the struct.
func TestMinimalAllocsCertWorker(t *testing.T) {
	// Cert worker use of allocation calls.
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	// Mock the DB.
	ctrl := gomock.NewController(t)
	conn := mock_db.NewMockConn(ctrl)

	conn.EXPECT().UpdateCerts(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(),
		gomock.Any()).AnyTimes().Return(nil)

	// Create mock certificates.
	N := 10
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))

	// Prepare the manager and worker for the test.
	manager := updater.NewManager(ctx, 1, conn, 1000, 1, nil)

	// The only interesting stage for this test is the one with the certificate worker.
	// For that purpose, we mock the source and sink.
	worker := updater.NewCertWorker(ctx, 0, manager, conn, 1)

	// Bundle the mock data.
	worker.Certs = certs

	// Measure allocations done in the mock library.
	extraAllocs := testing.AllocsPerRun(1, func() {
		conn.UpdateCerts(
			ctx,
			worker.CacheIds(),
			worker.CacheParents(),
			worker.CacheExpirations(),
			worker.CachePayloads(),
		)
	})
	require.Equal(t, 7.0, extraAllocs)

	// Measure the test function.
	worker.Certs = certs
	allocsPerRun := testing.AllocsPerRun(1, func() {
		worker.ProcessBundle()
		conn.UpdateCerts(
			ctx,
			worker.CacheIds(),
			worker.CacheParents(),
			worker.CacheExpirations(),
			worker.CachePayloads(),
		)
	})
	// Subtract the extra allocations not from the function.
	allocsPerRun -= extraAllocs

	// We should have 0 new allocations.
	t.Logf("%f allocations", allocsPerRun)
	require.Equal(t, 0.0, allocsPerRun)
}

// TestMinimalAllocsDomainWorker checks that the calls to deduplicate elements in DomainWorker
// do not need special memory allocations, due to the static fields present in the struct.
func TestMinimalAllocsDomainWorker(t *testing.T) {
	// Domain worker use of allocation calls.

	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	ctrl := gomock.NewController(t)
	conn := mock_db.NewMockConn(ctrl)

	conn.EXPECT().UpdateDomains(
		gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	conn.EXPECT().InsertDomainsIntoDirty(
		gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	conn.EXPECT().UpdateDomainCerts(
		gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

	// Create mock certificates.
	N := 10
	certs := toCertificates(random.BuildTestRandomCertTree(t, random.RandomLeafNames(t, N)...))

	// Prepare the manager and worker for the test.
	manager := updater.NewManager(ctx, 1, conn, 1000, 1, nil)
	worker := updater.NewDomainWorker(ctx, 0, manager, conn, 1)

	// Measure allocations done in the mock library.
	extraAllocs := testing.AllocsPerRun(1, func() {
		conn.InsertDomainsIntoDirty(ctx, worker.CloneDomainIDs())
	})
	require.Equal(t, 4.0, extraAllocs)
	extraAllocs += testing.AllocsPerRun(1, func() {
		conn.UpdateDomains(ctx, worker.CloneDomainIDs(), worker.CloneNames())
	})
	require.Equal(t, 4.0+5.0, extraAllocs)
	extraAllocs += testing.AllocsPerRun(1, func() {
		conn.UpdateDomainCerts(ctx, worker.CloneDomainIDs(), worker.CloneCertIDs())
	})
	require.Equal(t, 4.0+5.0+5.0, extraAllocs)

	// Bundle the mock data.
	bundle := extractDomains(certs)
	bundle = bundle[:min(len(bundle), manager.MultiInsertSize)] // limit to the size of the bundle
	worker.Domains = bundle

	// Measure the test function.
	allocsPerRun := testing.AllocsPerRun(1, func() {
		worker.ProcessBundle()
	})
	// Subtract the extra allocations not from the function.
	allocsPerRun -= extraAllocs

	// We should have 0 new allocations.
	t.Logf("%f allocations", allocsPerRun)
	require.Equal(t, 0.0, allocsPerRun)
}

func extractDomains(certs []updater.Certificate) []updater.DirtyDomain {
	domains := make([]updater.DirtyDomain, 0, len(certs))
	for _, c := range certs {
		// Iff the certificate is a leaf certificate it will have a non-nil names slice: insert
		// one entry per name.
		for _, name := range c.Names {
			domain := updater.DirtyDomain{
				DomainID: common.SHA256Hash32Bytes([]byte(name)),
				CertID:   c.CertID,
				Name:     name,
			}
			domains = append(domains, domain)
		}
	}
	return domains
}
