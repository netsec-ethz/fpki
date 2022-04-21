package pca

// for future use
import (
	pca "github.com/netsec-ethz/fpki/pkg/pca"
	"testing"
)

func Test_Config(t *testing.T) {
	_, err := pca.NewPCA("../../config/pca/pca_config")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

}
