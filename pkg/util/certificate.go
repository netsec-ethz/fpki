package util

import (
	"bytes"
	"fmt"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/netsec-ethz/fpki/pkg/common"
)

// ExtractNames returns a list of lists of names. Since each certificate contains several names,
// the function returns a collection of slices of names, extracted from each certificate's SAN.
func ExtractNames(certs []ctx509.Certificate) [][]string {
	names := make([][]string, len(certs))
	for i, c := range certs {
		names[i] = ExtractCertDomains(&c)
	}
	return names
}

// ExtractExpirations returns all expiration times in order.
func ExtractExpirations(certs []ctx509.Certificate) []time.Time {
	expirations := make([]time.Time, len(certs))
	for i, c := range certs {
		expirations[i] = c.NotAfter
	}
	return expirations
}

// ExtractPayloads returns the .Raw component of each certificate in order.
func ExtractPayloads(certs []ctx509.Certificate) [][]byte {
	payloads := make([][]byte, len(certs))
	for i, c := range certs {
		payloads[i] = c.Raw
	}
	return payloads
}

// SerializeCertificates serializes a sequence of certificates into their ASN.1 DER form.
func SerializeCertificates(certs []ctx509.Certificate) ([]byte, error) {
	buff := bytes.NewBuffer(nil)
	w := NewCertWriter(buff)
	n, err := w.Write(certs)
	if err != nil {
		return nil, err
	}
	if n != len(certs) {
		err = fmt.Errorf("not all certificates were serialized, only %d", n)
	}
	return buff.Bytes(), err
}

// DeserializeCertificates takes a stream of bytes that contains a sequence of certificates in
// ASN.1 DER form, and returns the original sequence of certificates.
func DeserializeCertificates(payload []byte) ([]ctx509.Certificate, error) {
	br := bytes.NewReader(payload)
	r := NewCertReader(br)
	return r.ReadAll()
}

// UnfoldCerts takes a slice of certificates and chains with the same length,
// and returns all certificates once, without duplicates, and the ID of the parent in the
// trust chain, or nil if the certificate is root.
// The parents returned slice has the same elements as the certificates returned slice.
// When a certificate is root, it's corresponding parents entry is nil.
// Additionally, all the names of the leaf certificates are returned in its corresponding position
// in the names slice iff the certificate is a leaf one. If it is not, nil is returned in that
// position instead.
//
// The leaf certificates are always returned at the head of the slice, which means, among others,
// that once a nil value is found in the names slice, the rest of the slice will be nil as well.
func UnfoldCerts(leafCerts []ctx509.Certificate, chains [][]*ctx509.Certificate,
) (
	certificates []ctx509.Certificate,
	certIDs []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	// extractNames is the function that extracts the names from a certificate. It starts being
	// a regular names extraction, but after processing all leaves it is assigned to a function
	// that always returns nil.
	extractNames := func(c *ctx509.Certificate) []string {
		return ExtractCertDomains(c)
	}
	// ChangeFcn changes extractNames to always return nil.
	changeFcn := func() {
		extractNames = func(*ctx509.Certificate) []string {
			return nil
		}
	}

	for len(leafCerts) > 0 {
		var pendingCerts []ctx509.Certificate
		var pendingChains [][]*ctx509.Certificate
		for i, c := range leafCerts {
			certificates = append(certificates, c)
			ID := common.SHA256Hash32Bytes(c.Raw)
			certIDs = append(certIDs, ID)
			var parentID *common.SHA256Output
			if len(chains[i]) > 0 {
				// The certificate has a trust chain (it is not root): add the first certificate
				// from the chain as the parent.
				parent := chains[i][0]
				ID := common.SHA256Hash32Bytes(parent.Raw)
				parentID = &ID
				// Add this parent to the back of the certs, plus the corresponding chain entry,
				// so that it's processed as a certificate.
				pendingCerts = append(pendingCerts, *parent)
				pendingChains = append(pendingChains, chains[i][1:])
			}
			parentIDs = append(parentIDs, parentID)
			names = append(names, extractNames(&c))
		}
		changeFcn() // This will change the function `extractNames` to always return nil.
		leafCerts = pendingCerts
		chains = pendingChains
	}
	return
}

// UnfoldCert takes a certificate with its trust chain and returns a ready-to-insert-in-DB
// collection of IDs and payloads for the certificate and its ancestry.
// Additionally, if the payload of any of the ancestors of the certificate is nil, this function
// interprets it as the ancestor is already present in the DB, and thus will omit returning it
// and any posterior ancestors.
func UnfoldCert(leafCert *ctx509.Certificate, certID common.SHA256Output,
	chain []*ctx509.Certificate, chainIDs []*common.SHA256Output,
) (
	certs []ctx509.Certificate,
	certIDs []common.SHA256Output,
	parentIDs []*common.SHA256Output,
	names [][]string,
) {

	certs = make([]ctx509.Certificate, 0, len(chainIDs)+1)
	certIDs = make([]common.SHA256Output, 0, len(chainIDs)+1)
	parentIDs = make([]*common.SHA256Output, 0, len(chainIDs)+1)
	names = make([][]string, 0, len(chainIDs)+1)

	// Always add the leaf certificate.
	certs = append(certs, *leafCert)
	certIDs = append(certIDs, certID)
	parentIDs = append(parentIDs, chainIDs[0])
	names = append(names, ExtractCertDomains(leafCert))
	// Add the intermediate certs iff their payload is not nil.
	i := 0
	for ; i < len(chain)-1; i++ {
		if chain[i] == nil {
			// This parent has been inserted already in DB. This implies that its own parent,
			// the grandparent of the leaf, must have been inserted as well; and so on.
			// There are no more parents to insert.
			return
		}
		certs = append(certs, *chain[i])
		certIDs = append(certIDs, *chainIDs[i])
		parentIDs = append(parentIDs, chainIDs[i+1])
		names = append(names, nil)
	}
	// Add the root certificate (no parent) iff we haven't inserted it yet.
	if chain[i] != nil {
		certs = append(certs, *chain[i])
		certIDs = append(certIDs, *chainIDs[i])
		parentIDs = append(parentIDs, nil)
		names = append(names, nil)
	}
	return
}
