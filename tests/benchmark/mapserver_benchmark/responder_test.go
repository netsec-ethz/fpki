package benchmark

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/stretchr/testify/require"
)

func BenchmarkResponderGetProof1M(b *testing.B) {
	benchmarkResponderGetProof(b, 1000*1000)
}

// BenchmarkResponderGetProof10M uses:
// Parallel req.	Time
// 			  64 	53.75s
// 			2000	55.17s
//		   20000	63.90s
func BenchmarkResponderGetProof10M(b *testing.B) {
	benchmarkResponderGetProof(b, 10*1000*1000)
}

func benchmarkResponderGetProof(b *testing.B, count int) {
	fmt.Println("Recreating updated DB ...")
	t0 := time.Now()
	swapBack := swapDBs(b)
	defer swapBack()
	resetDB(b)
	fmt.Printf("used %s\n", time.Since(t0))

	fmt.Println("Loading names ...")
	t0 = time.Now()
	names := make([]string, 0)
	f, err := os.Open("testdata/uniqueNames.txt")
	require.NoError(b, err)
	s := bufio.NewScanner(f)
	for s.Scan() {
		names = append(names, s.Text())
	}
	err = f.Close()
	require.NoError(b, err)
	fmt.Printf("used %s\n", time.Since(t0))

	// create responder and request proof for those names
	ctx, cancelF := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancelF()
	root, err := ioutil.ReadFile("testdata/root100K.bin")
	require.NoError(b, err)
	require.NotEmpty(b, root)
	responder, err := responder.NewMapResponder(ctx, root, 233)
	require.NoError(b, err)

	fmt.Println("Requesting ...")
	b.ResetTimer()

	// exec only once, assume perfect measuring. Because b.N is the number of iterations,
	// just mimic b.N executions.
	t0 = time.Now()
	parallelRequestLimit := 2000 // 2K requests simultaneously
	wg := &sync.WaitGroup{}
	var numRequests int64 = 0
	work := func(count int, names []string) {
		defer wg.Done()
		for i := 0; i < count; i++ {
			name := names[rand.Intn(len(names))]
			responses, err := responder.GetProof(ctx, name)
			// require.NoError(b, err)
			_ = err
			_ = responses
			atomic.AddInt64(&numRequests, 1)
		}
	}
	wg.Add(parallelRequestLimit)
	i := 0
	for ; i < count%parallelRequestLimit; i++ {
		go work(count/parallelRequestLimit+1, names)
	}
	for ; i < parallelRequestLimit; i++ {
		go work(count/parallelRequestLimit, names)
	}
	wg.Wait()
	fmt.Printf("done %d requests, used %s\n", numRequests, time.Since(t0))
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
