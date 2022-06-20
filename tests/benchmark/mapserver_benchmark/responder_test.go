package benchmark

import (
	"context"
	"fmt"
	"io/ioutil"
	"os/exec"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/stretchr/testify/require"
)

func BenchmarkResponderGetProof100K(b *testing.B) {
	benchmarkResponderGetProof(b, 100*1000)
}

func benchmarkResponderGetProof(b *testing.B, count int) {
	fmt.Println("Recreating updated DB ...")
	swapBack := swapDBs(b)
	defer swapBack()
	resetDB(b)

	fmt.Println("Loading certs ...")
	raw, err := gunzip(b, "testdata/certs.pem.gz")
	require.NoError(b, err)
	certs := loadCertsFromPEM(b, raw)
	require.GreaterOrEqual(b, len(certs), count)
	certs = certs[:count]

	require.NoError(b, err)
	require.Len(b, certs, count)

	// create responder and request proof for those names
	ctx, cancelF := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelF()
	root, err := ioutil.ReadFile("testdata/root100K.bin")
	require.NoError(b, err)
	require.NotEmpty(b, root)
	responder, err := responder.NewMapResponder(ctx, root, 233, 10)
	require.NoError(b, err)

	fmt.Println("Requesting ...")
	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 := time.Now()
	for _, cert := range certs {
		responses, err := responder.GetProof(ctx, cert.Subject.CommonName)
		// require.NoError(b, err)
		_ = err
		_ = responses
	}
	elapsed := time.Since(t0)
	require.NoError(b, err)
	for i := 1; i < b.N; i++ {
		time.Sleep(elapsed)
	}
}

func resetDB(t require.TestingT) {
	db.TruncateAllTablesForTest(t)

	err := exec.Command("bash", "-c", "zcat testdata/dump100K.sql.gz | mysql -u root fpki").Run()
	require.NoError(t, err)
}
