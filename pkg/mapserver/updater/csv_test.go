package updater

import (
	"encoding/base64"
	"encoding/csv"
	"os"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/stretchr/testify/require"
)

func TestEncodeToBase64(t *testing.T) {
	// Prepare a big enough storage.
	storage := make([]byte, 0, 1024)

	// Encode a byte slice.
	b := random.RandomBytesForTest(t, 100)

	allocs := tests.AllocsPerRun(func() {
		bytesToBase64WithStorage(&storage, b)
	})
	require.Equal(t, base64.StdEncoding.EncodeToString(b), string(storage))
	require.Equal(t, 0, allocs)

	// Encode a different byte slice.
	b = random.RandomBytesForTest(t, 100)
	allocs = tests.AllocsPerRun(func() {
		bytesToBase64WithStorage(&storage, b)
	})
	require.Equal(t, base64.StdEncoding.EncodeToString(b), string(storage))
	require.Equal(t, 0, allocs)
}

func TestRecordsForCert(t *testing.T) {
	storage := CreateStorage(1, 4, IdBase64Len, IdBase64Len, ExpTimeBase64Len, PayloadBase64Len)

	// One cert to records.
	c := randomCertificate(t)

	// First check allocations.
	// Remove payload (as it requires an allocation)
	payload := c.Cert.Raw
	c.Cert.Raw = nil
	allocs := tests.AllocsPerRun(func() {
		recordsForCert(storage[0], c)
	})
	require.Equal(t, 0, allocs)
	require.Len(t, storage, 1)
	row := storage[0]

	// Now check that the CSV encoding is correct.
	// Restore the payload and serialize again.
	c.Cert.Raw = payload
	recordsForCert(storage[0], c)

	require.Len(t, row, 4)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(c.CertID[:]), string(row[0]))
	require.Equal(t, idPtrToStr(c.ParentID), string(row[1]))
	require.Equal(t, c.Cert.NotAfter.Format(time.DateTime), string(row[2]))
	require.Equal(t, base64.StdEncoding.EncodeToString(c.Cert.Raw), string(row[3]))

	// Another cert to records.
	c = randomCertificate(t)
	c.ParentID = nil // force to root cert.
	recordsForCert(storage[0], c)
	require.Len(t, storage, 1)
	row = storage[0]
	require.Len(t, row, 4)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(c.CertID[:]), string(row[0]))
	require.Equal(t, idPtrToStr(c.ParentID), string(row[1]))
	require.Equal(t, c.Cert.NotAfter.Format(time.DateTime), string(row[2]))
	require.Equal(t, base64.StdEncoding.EncodeToString(c.Cert.Raw), string(row[3]))
}

func TestCreateCsvCerts(t *testing.T) {
	N := 1
	certs := make([]Certificate, N)
	for i := range certs {
		certs[i] = randomCertificate(t)
		// Remove payload, as it creates allocations.
		certs[i].Cert.Raw = nil
	}

	storage := CreateStorage(N, 4, IdBase64Len, IdBase64Len, ExpTimeBase64Len, PayloadBase64Len)
	filenameStorage := make([]byte, FilepathLen)

	// This function is similar to CreateCsvCerts, without actually writing a file.
	createCsvCerts := func(
		storage [][][]byte,
		certs []Certificate,
	) {
		noop := func([]byte, string, string, [][][]byte) (string, error) {
			return "", nil
		}
		writeRecordsWithStorage(
			storage,
			noop,
			filenameStorage,
			"mock-prefix",
			"mock-suffix",
			certs,
			recordsForCert,
		)
	}

	allocs := tests.AllocsPerRun(func() {
		createCsvCerts(storage, certs)
	})
	require.Equal(t, 0, allocs)
}

func TestRecordsForDirty(t *testing.T) {
	storage := CreateStorage(1, 1, IdBase64Len)

	// One domain to domain_certs records.
	d := randomDirtyDomain(t)
	allocs := tests.AllocsPerRun(func() {
		recordsForDirty(storage[0], d)
	})
	require.Equal(t, 0, allocs)
	require.Len(t, storage, 1)
	row := storage[0]
	require.Len(t, row, 1)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))

	// Another cert to records.
	d = randomDirtyDomain(t)
	recordsForDirty(storage[0], d)
	require.Len(t, storage, 1)
	row = storage[0]
	require.Len(t, row, 1)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))
}

func TestRecordsForDomains(t *testing.T) {
	storage := CreateStorage(1, 2, IdBase64Len, DomainNameLen)

	// One domain to domain_certs records.
	d := randomDirtyDomain(t)
	allocs := tests.AllocsPerRun(func() {
		recordsForDomains(storage[0], d)
	})
	require.Equal(t, 0, allocs)
	require.Len(t, storage, 1)
	row := storage[0]
	require.Len(t, row, 2)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))
	require.Equal(t, d.Name, string(row[1]))

	// Another cert to records.
	d = randomDirtyDomain(t)
	recordsForDomains(storage[0], d)
	require.Len(t, storage, 1)
	row = storage[0]
	require.Len(t, row, 2)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))
	require.Equal(t, d.Name, string(row[1]))
}

func TestRecordsForDomainCerts(t *testing.T) {
	storage := CreateStorage(1, 2, IdBase64Len, IdBase64Len)

	// One domain to domain_certs records.
	d := randomDirtyDomain(t)
	allocs := tests.AllocsPerRun(func() {
		recordsForDomainCerts(storage[0], d)
	})
	require.Equal(t, 0, allocs)
	require.Len(t, storage, 1)
	row := storage[0]
	require.Len(t, row, 2)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))
	require.Equal(t, base64.StdEncoding.EncodeToString(d.CertID[:]), string(row[1]))

	// Another cert to records.
	d = randomDirtyDomain(t)
	recordsForDomainCerts(storage[0], d)
	require.Len(t, storage, 1)
	row = storage[0]
	require.Len(t, row, 2)
	for i, field := range row {
		t.Logf("field %d: %s", i, string(field))
	}
	require.Equal(t, base64.StdEncoding.EncodeToString(d.DomainID[:]), string(row[0]))
	require.Equal(t, base64.StdEncoding.EncodeToString(d.CertID[:]), string(row[1]))
}

func TestWriteCsvCerts(t *testing.T) {
	storage := CreateStorage(10, 4,
		IdBase64Len,
		IdBase64Len,
		ExpTimeBase64Len,
		PayloadBase64Len,
	)
	filenameStorage := make([]byte, FilepathLen)
	certs := make([]Certificate, 3)
	for i := range certs {
		certs[i] = randomCertificate(t)
	}

	tempFilename, err := CreateCsvCerts(storage, filenameStorage, certs)
	require.NoError(t, err)

	t.Logf("temp filepath: %s", tempFilename)
	// Open csv and check.
	f, err := os.Open(tempFilename)
	require.NoError(t, err)
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Parse contents and store.
	require.Equal(t, len(certs), len(rows))
	ids := make([]*common.SHA256Output, len(certs))
	parents := make([]*common.SHA256Output, len(certs))
	expTimes := make([]time.Time, len(certs))
	payloads := make([][]byte, len(certs))
	for i, row := range rows {
		require.Equal(t, 4, len(row))
		// ID, parentID, time, payload.
		id, err := base64.StdEncoding.DecodeString(row[0])
		require.NoError(t, err)
		parent, err := base64.StdEncoding.DecodeString(row[1])
		require.NoError(t, err)
		expTime, err := time.Parse(time.DateTime, row[2])
		require.NoError(t, err)
		payload, err := base64.StdEncoding.DecodeString(row[3])
		require.NoError(t, err)

		ids[i] = (*common.SHA256Output)(id)
		parents[i] = (*common.SHA256Output)(parent)
		expTimes[i] = expTime
		payloads[i] = payload
	}
	// Check equality to original values.
	for i, orig := range certs {
		require.Equal(t, &orig.CertID, ids[i])
		require.Equal(t, orig.ParentID, parents[i])
		require.Equal(t, orig.Cert.NotAfter, expTimes[i])
		require.Equal(t, orig.Cert.Raw, payloads[i])
	}

	// Finally, remove temporary file.
	require.NoError(t, os.Remove(tempFilename))
}

func randomCertificate(t tests.T) Certificate {
	name := random.RandomLeafNames(t, 1)[0]
	return Certificate{
		CertID:   random.RandomIDsForTest(t, 1)[0],
		ParentID: random.RandomIDPtrsForTest(t, 1)[0],
		Cert:     random.RandomX509Cert(t, name),
		Names:    []string{name},
	}
}

func randomDirtyDomain(t tests.T) DirtyDomain {
	name := random.RandomLeafNames(t, 1)[0]
	id := common.SHA256Hash32Bytes([]byte(name))
	return DirtyDomain{
		DomainID: id,
		CertID:   random.RandomIDsForTest(t, 1)[0],
		Name:     name,
	}
}

func idPtrToStr(idPtr *common.SHA256Output) string {
	if idPtr == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString((*idPtr)[:])
}
