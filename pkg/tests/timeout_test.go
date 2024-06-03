package tests_test

import (
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

// TestTestOrTimeout checks that, even with "-race" enabled, the TestOrTimeout function works.
func TestTestOrTimeout(t *testing.T) {
	tests.TestOrTimeout(t, func(t tests.T) {
		require.True(t, true)
	}, tests.WithTimeout(time.Millisecond))
}
