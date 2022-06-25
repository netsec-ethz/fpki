package db

import (
	"fmt"

	"github.com/stretchr/testify/require"
)

type testingT struct{}

func (t *testingT) Errorf(format string, args ...interface{}) {
	str := fmt.Sprintf(format, args...)
	panic(str)
}
func (t *testingT) FailNow() {
	panic("")
}

// TruncateAllTablesWithoutTestObject will truncate all tables in DB. This function should
// be used only while testing.
func TruncateAllTablesWithoutTestObject() {
	t := &testingT{}
	TruncateAllTablesForTest(t)
}

// TruncateAllTablesForTest will truncate all tables in DB. This function should be used
// only in tests.
func TruncateAllTablesForTest(t require.TestingT) {
	db, err := Connect(nil)
	require.NoError(t, err)
	c := db.(*mysqlDB)
	require.NotNil(t, c)

	_, err = c.db.Exec("TRUNCATE fpki.domainEntries;")
	require.NoError(t, err)
	_, err = c.db.Exec("TRUNCATE fpki.tree;")
	require.NoError(t, err)
	_, err = c.db.Exec("TRUNCATE fpki.updates;")
	require.NoError(t, err)

	err = db.Close()
	require.NoError(t, err)
}

// GetDomainNamesForTest will get rows count of domain entries table
// be used only while testing.
func GetDomainNamesForTest() int {
	t := &testingT{}
	return getDomainNames(t)
}

func getDomainNames(t require.TestingT) int {
	db, err := Connect(nil)
	require.NoError(t, err)
	c := db.(*mysqlDB)
	require.NotNil(t, c)

	var count int
	err = c.db.QueryRow("SELECT COUNT(*) FROM domainEntries;").Scan(&count)
	require.NoError(t, err)

	err = db.Close()
	require.NoError(t, err)

	return count
}
