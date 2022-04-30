package pca

// for future use
import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Config(t *testing.T) {
	_, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")
}
