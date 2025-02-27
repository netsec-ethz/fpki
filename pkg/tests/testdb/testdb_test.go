package testdb

import (
	"context"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

// TestConfigureTestDB checks that the ConfigureTestDB function works properly.
func TestConfigureTestDB(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()
	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		conf, removeF := ConfigureTestDB(t)
		require.NotEmpty(t, conf.Values)
		removeF()
	})
}

func TestCreateTestDB(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelF()

	tests.TestOrTimeout(t, tests.WithContext(ctx), func(t tests.T) {
		name := "check_create_test_db"
		err := createTestDB(ctx, name)
		require.NoError(t, err)
	})
}
