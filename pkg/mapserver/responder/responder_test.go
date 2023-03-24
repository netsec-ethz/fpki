package responder

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

func TestProofWithPoP(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()

	dbName := t.Name()
	config := db.NewConfig(mysql.WithDefaults(), db.WithDB(dbName))

	err := tests.CreateTestDB(ctx, dbName)
	require.NoError(t, err)
	defer func() {
		err = tests.RemoveTestDB(ctx, config)
		require.NoError(t, err)
	}()
}
