package mysql_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/testdb"
)

func TestInsertPerformance(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into the `certs` table.
	NCerts := 1_000_000
	// NCerts := 100_000
	PayloadSize := 4_000
	allCerts := make([]common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		binary.LittleEndian.PutUint64(allCerts[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Function that inserts certificates and payload.
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)

	t.Run("MyISAM", func(t *testing.T) {
		// Create a certs table using InnoDB.
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE insert_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			  payload LONGBLOB,
	
			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		batchInsertCerts(ctx, t, conn, "insert_test", mockExp, mockPayload, allCerts, 2000)
	})

	// Note that InnoDB works much faster with insertions with AUTO INCREMENT.
	t.Run("InnoDB", func(t *testing.T) {
		// Create a certs table using InnoDB.
		str := "DROP TABLE IF EXISTS `insert_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE insert_test (
			auto_id BIGINT NOT NULL AUTO_INCREMENT,
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,
	
			PRIMARY KEY(auto_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		batchInsertCerts(ctx, t, conn, "insert_test", mockExp, mockPayload, allCerts, 2000)
	})
}

func TestReadPerformance(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 200*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into the `certs` table.
	// NCerts := 100_000_000
	NCerts := 100_000
	PayloadSize := 4_000
	allCerts := make([]common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		binary.LittleEndian.PutUint64(allCerts[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Function that inserts certificates and payload.
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)

	// Create a certs table using InnoDB.
	str := "DROP TABLE IF EXISTS `read_test`"
	_, err := conn.DB().ExecContext(ctx, str)
	require.NoError(t, err)
	str = `CREATE TABLE read_test (
			cert_id VARBINARY(32) NOT NULL,
			expiration DATETIME NOT NULL,
			payload LONGBLOB,
	
			PRIMARY KEY(cert_id)
		) ENGINE=MyISAM CHARSET=binary COLLATE=binary;`
	_, err = conn.DB().ExecContext(ctx, str)
	require.NoError(t, err)

	batchInsertCerts(ctx, t, conn, "read_test", mockExp, mockPayload, allCerts, 2000)
	t.Log("data inserted")

	str = "ALTER TABLE read_test ENGINE=InnoDB"
	_, err = conn.DB().ExecContext(ctx, str)
	t.Log("engine altered")
	require.NoError(t, err)
}

func batchInsertCerts(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	tableName string,
	mockExp time.Time,
	mockPayload []byte,
	certs []common.SHA256Output,
	batchSize int) {

	wg := sync.WaitGroup{}
	i := 0
	for ; i < len(certs); i += batchSize {
		wg.Add(1)
		s := i
		e := min(len(certs), i+batchSize)
		go func() {
			defer wg.Done()
			insertCerts(ctx, t, conn, tableName, mockExp, mockPayload, certs[s:e])
		}()
	}
	wg.Wait()
}

func insertCerts(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	tableName string,
	mockExp time.Time,
	mockPayload []byte,
	certs []common.SHA256Output) {

	str := fmt.Sprintf("REPLACE INTO %s (cert_id,expiration,payload) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(certs), 3)) // 3 columns
	data := make([]interface{}, 3*len(certs))
	for i := range certs {
		data[i*3] = certs[i][:]   // ID
		data[i*3+1] = mockExp     // Expiration
		data[i*3+2] = mockPayload // Payload
	}
	res, err := conn.DB().ExecContext(ctx, str, data...)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(len(certs)))
}
