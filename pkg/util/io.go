package util

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/csv"
	"io/ioutil"
	"os"
	"strings"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

type GzipReader struct {
	f        *os.File
	gzreader *gzip.Reader
}

func (r *GzipReader) Read(buff []byte) (int, error) {
	return r.gzreader.Read(buff)
}

func (r *GzipReader) Close() error {
	if err := r.gzreader.Close(); err != nil {
		return err
	}
	return r.f.Close()
}

func NewGzipReader(filename string) (*GzipReader, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return &GzipReader{
		f:        f,
		gzreader: z,
	}, nil
}

func ReadAllGzippedFile(filename string) ([]byte, error) {
	r, err := NewGzipReader(filename)
	if err != nil {
		return nil, err
	}
	buff, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return buff, r.Close()
}

// LoadCertsAndChainsFromCSV returns a ready to insert-in-DB collection of the leaf certificate
// payload, its ID, its parent ID, and its names, for each certificate and its ancestry chain.
// The returned names contains nil unless the corresponding certificate is a leaf certificate.
func LoadCertsAndChainsFromCSV(
	fileContents []byte,
) (payloads []*ctx509.Certificate,
	IDs []*common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
	errRet error,
) {

	r := bytes.NewReader(fileContents)
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1 // don't check number of fields

	records, err := reader.ReadAll()
	if err != nil {
		errRet = err
		return
	}
	leafs := make([]*ctx509.Certificate, 0, len(payloads))
	chains := make([][]*ctx509.Certificate, 0, len(payloads))
	for _, fields := range records {
		if len(fields) == 0 {
			continue
		}

		cert, err := parseCertFromCSVField(fields[CertificateColumn])
		if err != nil {
			errRet = err
			return
		}
		leafs = append(leafs, cert)

		// Parse the chain.
		// The certificate chain is a list of base64 strings separated by semicolon (;).
		strs := strings.Split(fields[CertChainColumn], ";")
		chain := make([]*ctx509.Certificate, len(strs))
		for i, s := range strs {
			chain[i], err = parseCertFromCSVField(s)
			if err != nil {
				errRet = err
				return
			}
		}
		chains = append(chains, chain)
	}

	// Unfold the received certificates.
	payloads, IDs, parentIDs, names = UnfoldCerts(leafs, chains)
	return
}

// LoadPoliciesFromRaw can load RPCs, SPs, RCSRs, PCRevocations, SPRTs, and PSRs from their
// serialized form.
func LoadPoliciesFromRaw(b []byte) ([]common.PolicyObject, []*common.SHA256Output, error) {
	obj, err := common.FromJSON(b)
	if err != nil {
		return nil, nil, err
	}
	// The returned object should be of type list.
	pols, err := ToTypedSlice[common.PolicyObject](obj)
	if err != nil {
		return nil, nil, err
	}

	ids := make([]*common.SHA256Output, len(pols))
	for i, pol := range pols {
		id := common.SHA256Hash32Bytes(pol.Raw())
		ids[i] = &id
	}

	return pols, ids, nil

}

// parseCertFromCSVField takes a row from a CSV encoding certs and chains in base64 and returns
// the CT x509 Certificate or error.
func parseCertFromCSVField(field string) (*ctx509.Certificate, error) {
	// Base64 to raw bytes.
	rawBytes, err := base64.StdEncoding.DecodeString(field)
	if err != nil {
		return nil, err
	}
	// Parse the certificate.
	cert, err := ctx509.ParseCertificate(rawBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
