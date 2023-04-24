package util

import (
	"encoding/pem"
	"io"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

type CertWriter struct {
	w io.Writer
}

func NewCertWriter(w io.Writer) *CertWriter {
	return &CertWriter{
		w: w,
	}
}

// Write acts like a io.Writer Write method, but for certificates.
func (w *CertWriter) Write(certs []*ctx509.Certificate) (int, error) {
	for i, c := range certs {
		b := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}
		err := pem.Encode(w.w, b)
		if err != nil {
			return i, err
		}
	}
	return len(certs), nil
}
