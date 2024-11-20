package updater

import (
	"encoding/base64"
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
	var got string
	allocs := tests.AllocsPerRun(func() {
		got = bytesToBase64WithStorage(&storage, b)
	})
	require.Equal(t, base64.StdEncoding.EncodeToString(b), got)
	require.Equal(t, got, string(storage))
	require.Equal(t, 0, allocs)

	// Encode a different byte slice.
	b = random.RandomBytesForTest(t, 100)
	allocs = tests.AllocsPerRun(func() {
		got = bytesToBase64WithStorage(&storage, b)
	})
	require.Equal(t, base64.StdEncoding.EncodeToString(b), got)
	require.Equal(t, 0, allocs)
}

func TestRecordsForCert(t *testing.T) {
	storage := CreateStorage(1, 4, IdBase64Len, IdBase64Len, ExpTimeBase64Len, PayloadBase64Len)

	// One cert to records.
	c := randomCertificate(t)
	allocs := tests.AllocsPerRun(func() {
		recordsForCert(storage[0], c)
	})
	require.Equal(t, 0, allocs)
	require.Len(t, storage, 1)
	row := storage[0]
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

func randomCertificate(t tests.T) Certificate {
	name := random.RandomLeafNames(t, 1)[0]
	return Certificate{
		CertID:   random.RandomIDsForTest(t, 1)[0],
		ParentID: random.RandomIDPtrsForTest(t, 1)[0],
		Cert:     random.RandomX509Cert(t, name),
		Names:    []string{name},
	}
}

func idPtrToStr(idPtr *common.SHA256Output) string {
	if idPtr == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString((*idPtr)[:])
}
