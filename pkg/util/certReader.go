package util

import (
	"encoding/pem"
	"io"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

type CertReader struct {
	r          io.Reader
	storage    []byte
	buff       []byte
	eofReached bool
}

func NewCertReader(r io.Reader) *CertReader {
	return &CertReader{
		r:       r,
		storage: make([]byte, 1024*1024),
		buff:    nil,
	}
}

// Read reads as many certificates as the `certs` slice has or end-of-stream.
func (r *CertReader) Read(certs []*ctx509.Certificate) (int, error) {
	certPointers := certs
	for len(certPointers) > 0 {
		// Move len(buff) bytes to beginning of storage.
		n := copy(r.storage[:], r.buff)
		// Set buff to be the remaining of the storage.
		r.buff = r.storage[n:]

		// Read as much as possible.
		newBytes, err := r.r.Read(r.buff)
		if err != nil && err != io.EOF {
			return 0, err
		}
		// Set buff to beginning of storage and until last read byte.
		r.buff = r.storage[:n+newBytes]

		if newBytes == 0 {
			if err != io.EOF {
				// Storage support might be too small to fit this PEM block. Increase by double
				// its size and try again; the copy at the beginning of the loop will restore
				// the original contents to this new buffer.
				r.storage = make([]byte, 2*len(r.storage))
				continue
			}
			// End of File.
			r.eofReached = true
		}

		// Proceed to parse as many CERTIFICATE PEM blocks as possible.
		var block *pem.Block
		for len(certPointers) > 0 { // do-while block != nil && block.Type == CERTIFICATE
			block, r.buff = pem.Decode(r.buff)
			if block == nil {
				// No PEM block found, try to read more data and try again.
				break
			}
			if block.Type != "CERTIFICATE" {
				// Wrong PEM block, try to find another one.
				continue
			}
			// It must be a certificate. Complain if parsing fails.
			c, err := ctx509.ParseTBSCertificate(block.Bytes)
			if err != nil {
				return 0, err
			}
			certPointers[0] = c
			certPointers = certPointers[1:]
		}
		if r.eofReached {
			break
		}
	}
	return len(certs) - len(certPointers), nil
}

// ReadAll reads all pending certificates from the internal reader this CertReader was created
// from. This function is usually called right after creating the CertReader.
func (r *CertReader) ReadAll() ([]*ctx509.Certificate, error) {
	certs := make([]*ctx509.Certificate, 1)
	for {
		n, err := r.Read(certs[len(certs)-1:]) // read one certificate, at the end of the slice
		if err != nil {
			return nil, err
		}
		if n == 0 {
			certs = certs[:len(certs)-1] // remove the empty gap
			break
		}
		certs = append(certs, nil) // make room for one more, with an empty gap
	}
	return certs, nil
}
