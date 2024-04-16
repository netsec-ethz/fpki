package mysql_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
	"github.com/stretchr/testify/require"
)

func TestConcurrentSleep(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Test that sleep works as expected.
	S := 1
	t0 := time.Now()
	conn.DB().QueryContext(ctx, "SELECT SLEEP(?);", S)
	got := int(time.Since(t0).Seconds())
	require.GreaterOrEqual(t, got, S)

	// Concurrent with one connection.
	S = 3
	wg := sync.WaitGroup{}
	wg.Add(2)
	fcn := func(conn db.Conn) {
		defer wg.Done()

		fmt.Printf("begin sleep %s\n", time.Now().Format(time.StampMilli))
		conn.DB().QueryContext(ctx, "SELECT SLEEP(?);", S)
		fmt.Printf("end sleep %s\n", time.Now().Format(time.StampMilli))
	}
	t0 = time.Now()
	go fcn(conn)
	go fcn(conn)

	wg.Wait()
	got = int(time.Since(t0).Seconds())
	require.GreaterOrEqual(t, got, S)
	require.Less(t, got, S*2)
}

// TestConcurrentInsert
// WARNING!!: test is SLOW.
func TestConcurrentInsert(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert e.g. in the `certs` table.
	N := 1000
	allCerts := make([]common.SHA256Output, N)
	for i := 0; i < N; i++ {
		binary.LittleEndian.PutUint64(allCerts[i][:], uint64(i))
	}

	// Function that inserts certificates and payload.
	mockPayload := make([]byte, 1_000_000)
	mockExp := time.Unix(42, 0)
	insertFcn := func(certs []common.SHA256Output) {
		for _, cert := range certs {
			str := "REPLACE INTO certs (cert_id,expiration,payload) VALUES (?,?,?)"
			res, err := conn.DB().ExecContext(ctx, str, cert[:], mockExp, mockPayload)
			require.NoError(t, err)
			n, err := res.RowsAffected()
			require.NoError(t, err)
			require.GreaterOrEqual(t, n, int64(1))
		}
	}

	// Check how long it takes to insert half of it sequentially.
	t0 := time.Now()
	insertFcn(allCerts[:N/2])
	tSeq := time.Since(t0).Seconds()
	t.Logf("took %fs to insert half", tSeq)

	// Run in parallel
	wg := sync.WaitGroup{}
	parallel := func(certs []common.SHA256Output) {
		defer wg.Done()
		insertFcn(certs)
	}
	wg.Add(2)
	t0 = time.Now()
	go parallel(allCerts[:N/2])
	go parallel(allCerts[N/2:])
	wg.Wait()
	tPara := time.Since(t0).Seconds()
	t.Logf("took %fs to insert concurrently all", tPara)
	// We expect the 2 calls to parallel() to need similar to one call to parallel.
	epsilon := tSeq / 10.0
	require.Greater(t, tPara, tSeq+epsilon)
	require.Less(t, tPara, tSeq*2) // But much faster than two calls to sequential.
}

func TestConcurrentFibonacci(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Fibonacci recursive procedure to use as a benchmark (disk independent)
	str := "DROP PROCEDURE IF EXISTS fibonacci;"
	_, err := conn.DB().ExecContext(ctx, str)
	require.NoError(t, err)

	str = `CREATE PROCEDURE fibonacci(IN n INT, OUT out_fib INT)
	BEGIN
	  DECLARE n_1 INT;
	  DECLARE n_2 INT;
	
	  IF (n=0) THEN
		SET out_fib=0;
	  ELSEIF (n=1) THEN
		SET out_fib=1;
	  ELSE
		CALL fibonacci(n-1, n_1);
		CALL fibonacci(n-2, n_2);
		SET out_fib=(n_1 + n_2);
	  END IF;
	END`
	_, err = conn.DB().ExecContext(ctx, str)
	require.NoError(t, err)

	// Function to call fibonacci(28) on the DB.
	fib := func(conn db.Conn) {
		_, err := conn.DB().ExecContext(ctx, "SET max_sp_recursion_depth=255")
		require.NoError(t, err)
		_, err = conn.DB().ExecContext(ctx, "CALL fibonacci(28, @aux)")
		require.NoError(t, err)
		row := conn.DB().QueryRowContext(ctx, "SELECT @aux")
		require.NoError(t, row.Err())
		var res int
		err = row.Scan(&res)
		require.NoError(t, err)
		t.Logf("fib = %d", res)
	}

	// Measure how long it takes for fibonacci(28)
	t0 := time.Now()
	fib(conn)
	tSeq := time.Since(t0).Seconds()
	t.Logf("took %fs to call fib() once", tSeq)

	// Define a concurrent caller for fib().
	wg := sync.WaitGroup{}
	concurrent := func(conn db.Conn) {
		defer wg.Done()

		fib(conn)
	}

	// Now call twice concurrently but using the same connection.
	wg.Add(2)
	t0 = time.Now()
	go concurrent(conn)
	go concurrent(conn)
	wg.Wait()
	tConc := time.Since(t0).Seconds()
	t.Logf("took %fs to call fib() twice with one conn", tConc)

}
