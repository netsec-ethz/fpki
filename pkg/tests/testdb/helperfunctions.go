package testdb

import (
	"context"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/stretchr/testify/require"
)

// TruncateAllTablesWithoutTestObject will truncate all tables in DB. This function should
// be used only while testing.
func TruncateAllTablesWithoutTestObject() {
	t := &testingT{}
	TruncateAllTablesForTest(t)
}

// TruncateAllTablesForTest will truncate all tables in DB. This function should be used
// only in tests.
func TruncateAllTablesForTest(t require.TestingT) {
	db, err := mysql.Connect(nil)
	require.NoError(t, err)

	err = db.TruncateAllTables(context.Background())
	require.NoError(t, err)

	err = db.Close()
	require.NoError(t, err)
}

// GetDomainCountWithoutTestObject will get rows count of domain entries table
// be used only while testing.
func GetDomainCountWithoutTestObject() int {
	t := &testingT{}
	return getDomainNames(t)
}

func getDomainNames(t require.TestingT) int {
	db, err := mysql.Connect(nil)
	require.NoError(t, err)

	var count int
	err = db.DB().QueryRow("SELECT COUNT(*) FROM domainEntries;").Scan(&count)
	require.NoError(t, err)

	err = db.Close()
	require.NoError(t, err)

	return count
}

type testingT struct{}

func (t *testingT) Errorf(format string, args ...interface{}) {
	str := fmt.Sprintf(format, args...)
	panic(str)
}
func (t *testingT) FailNow() {
	panic("")
}
