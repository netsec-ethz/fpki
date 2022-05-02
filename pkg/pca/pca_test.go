package pca

// for future use
// Testing of PCA is in the integration test, because it also need the help of domain owner.
// This file will be used for future logics.
import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Config(t *testing.T) {
	_, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")
}
