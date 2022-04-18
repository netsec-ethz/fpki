package main

// for future use
import (
	pca "pca.FPKI.github.com"
	"testing"
)

func Test_Config(t *testing.T) {
	_, err := pca.NewPCA("/Users/yongzhe/Desktop/fpki/config/pca/pcaConfig")
	if err != nil {
		t.Errorf(err.Error())
		return
	}

}
