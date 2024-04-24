package mysql_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	mysqllib "github.com/go-sql-driver/mysql"
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
	PayloadSize := 4_000
	allCertIDs := make([]*common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		allCertIDs[i] = new(common.SHA256Output)
		binary.LittleEndian.PutUint64(allCertIDs[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Function that inserts certificates and payload.
	mockExp := time.Unix(42, 0)
	mockPayload := make([]byte, PayloadSize)

	t.Run("MyISAM", func(t *testing.T) {
		// Create a certs-like table using InnoDB.
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

		callFuncPerIDBatch(2000, allCertIDs, func(IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "insert_test", IDs, mockExp, mockPayload)
		})
	})

	// Note that InnoDB works much faster with insertions with AUTO INCREMENT.
	t.Run("InnoDB", func(t *testing.T) {
		// Create a certs-like table using MyISAM.
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

		callFuncPerIDBatch(2000, allCertIDs, func(IDs []*common.SHA256Output) {
			insertCerts(ctx, t, conn, "insert_test", IDs, mockExp, mockPayload)
		})
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
	NCerts := 100_000
	PayloadSize := 4_000
	allCertIDs := make([]*common.SHA256Output, NCerts)
	for i := 0; i < NCerts; i++ {
		allCertIDs[i] = new(common.SHA256Output)
		binary.LittleEndian.PutUint64(allCertIDs[i][:], uint64(i))
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

	callFuncPerIDBatch(2000, allCertIDs, func(IDs []*common.SHA256Output) {
		insertCerts(ctx, t, conn, "read_test", IDs, mockExp, mockPayload)
	})
	t.Log("data inserted")

	str = "ALTER TABLE read_test ENGINE=InnoDB"
	_, err = conn.DB().ExecContext(ctx, str)
	t.Log("engine altered")
	require.NoError(t, err)
}

func TestInsertDirtyInnoDB(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelF()

	// Configure a test DB.
	config, removeF := testdb.ConfigureTestDB(t)
	defer removeF()

	// Connect to the DB.
	conn := testdb.Connect(t, config)
	defer conn.Close()

	// Create lots of data to insert into a mock `dirty` table.
	NDomains := 100_000
	allDomainIDs := make([]*common.SHA256Output, NDomains)
	for i := 0; i < NDomains; i++ {
		allDomainIDs[i] = new(common.SHA256Output)
		binary.LittleEndian.PutUint64(allDomainIDs[i][:], uint64(i))
	}
	t.Log("Mock data ready in memory")

	// Call each thread with different domain IDs separately:
	t.Run("non_overlapping_ids", func(t *testing.T) {
		// Create a dirty table using InnoDB.
		str := "DROP TABLE IF EXISTS `dirty_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE dirty_test (
			auto_id bigint NOT NULL AUTO_INCREMENT,
			domain_id varbinary(32) NOT NULL,
			PRIMARY KEY (auto_id),
			UNIQUE KEY domain_id (domain_id)
			) ENGINE=InnoDB AUTO_INCREMENT=917012 DEFAULT CHARSET=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		callFuncPerIDBatch(100_000, allDomainIDs, func(IDs []*common.SHA256Output) {
			err := insertIntoDirty(ctx, conn, "dirty_test", IDs)
			require.NoError(t, err)
		})
	})

	// Now call many threads with the same IDs.
	t.Run("clashing_ids", func(t *testing.T) {
		// Create a dirty table using InnoDB.
		str := "DROP TABLE IF EXISTS `dirty_test`"
		_, err := conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)
		str = `CREATE TABLE dirty_test (
			auto_id bigint NOT NULL AUTO_INCREMENT,
			domain_id varbinary(32) NOT NULL,
			PRIMARY KEY (auto_id),
			UNIQUE KEY domain_id (domain_id)
			) ENGINE=InnoDB AUTO_INCREMENT=917012 DEFAULT CHARSET=binary;`
		_, err = conn.DB().ExecContext(ctx, str)
		require.NoError(t, err)

		errors := make([]error, 4)
		wg := sync.WaitGroup{}
		wg.Add(len(errors))
		for i := 0; i < len(errors); i++ {
			i := i
			go func() {
				defer wg.Done()

				// The same IDs, at the same time.
				errors[i] = insertIntoDirty(ctx, conn, "dirty_test", allDomainIDs)
			}()
		}
		wg.Wait()

		// We expect one non-error, and the errors on the rest of the routines.
		successCount := 0
		for _, err := range errors {
			if err != nil {
				require.Error(t, err)
				require.IsType(t, (*mysqllib.MySQLError)(nil), err)
				err := err.(*mysqllib.MySQLError)
				require.Equal(t, uint16(1213), err.Number,
					"got error code: %d\nMySQL Message: %s", err.Number, err.Message)
			} else {
				successCount++
			}
		}
		require.Equal(t, 1, successCount)
	})

}

func callFuncPerIDBatch(
	batchSize int,
	IDs []*common.SHA256Output,
	theFunc func(IDs []*common.SHA256Output),
) {

	wg := sync.WaitGroup{}
	i := 0
	for ; i < len(IDs); i += batchSize {
		wg.Add(1)
		s := i
		e := min(len(IDs), i+batchSize)
		go func() {
			defer wg.Done()
			theFunc(IDs[s:e])
		}()
	}
	wg.Wait()
}

func insertCerts(
	ctx context.Context,
	t tests.T,
	conn db.Conn,
	tableName string,
	certIDs []*common.SHA256Output,
	mockExp time.Time,
	mockPayload []byte,
) {

	str := fmt.Sprintf("REPLACE INTO %s (cert_id,expiration,payload) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(certIDs), 3)) // 3 columns
	data := make([]interface{}, 3*len(certIDs))
	for i := range certIDs {
		id := *certIDs[i]
		data[i*3] = id[:]         // ID
		data[i*3+1] = mockExp     // Expiration
		data[i*3+2] = mockPayload // Payload
	}
	res, err := conn.DB().ExecContext(ctx, str, data...)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.GreaterOrEqual(t, n, int64(len(certIDs)))
}

func insertIntoDirty(
	ctx context.Context,
	conn db.Conn,
	tableName string,
	domainIDs []*common.SHA256Output) error {

	// Make the list of domain IDs unique.
	domainIDsSet := make(map[common.SHA256Output]struct{})
	for _, id := range domainIDs {
		domainIDsSet[*id] = struct{}{}
	}

	// It fails with all of them: "REPLACE INTO", "INSERT", or "INSERT IGNORE",
	// because there is a UNIQUE constraint (key) that needs locking.
	str := fmt.Sprintf("INSERT IGNORE INTO %s (domain_id) VALUES %s",
		tableName,
		mysql.RepeatStmt(len(domainIDsSet), 1)) // 1 column
	data := make([]interface{}, len(domainIDsSet))
	i := 0
	for k := range domainIDsSet {
		k := k
		data[i] = k[:] // ID
		i++
	}
	_, err := conn.DB().ExecContext(ctx, str, data...)
	return err
}
