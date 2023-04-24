package util

import (
	"fmt"
	"os"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
)

func TestDeserializeCertificates(t *testing.T) {
	// Load three certificates.
	N := 3
	f, err := os.Open("../../tests/testdata/3-certs.pem")
	require.NoError(t, err)
	r := NewCertReader(f)
	certs := make([]*ctx509.Certificate, N)
	n, err := r.Read(certs)
	require.NoError(t, err)
	require.Equal(t, N, n)

	// Serialize them.
	payload, err := SerializeCertificates(certs)
	require.NoError(t, err)
	require.Greater(t, len(payload), 0)

	// Deserialize them.
	newCerts, err := DeserializeCertificates(payload)
	require.NoError(t, err)
	require.Len(t, newCerts, N)

	// Compare their contents.
	require.ElementsMatch(t, certs, newCerts)
}

func TestUnfoldCerts(t *testing.T) {
	// `a` and `b` are leaves. `a` is root, `b` has `c`->`d` as its trust chain.
	a := &ctx509.Certificate{
		Raw: []byte{0},
		Subject: pkix.Name{
			CommonName: "a",
		},
		DNSNames: []string{"a", "a", "a.com"},
	}
	b := &ctx509.Certificate{
		Raw: []byte{1},
		Subject: pkix.Name{
			CommonName: "b",
		},
		DNSNames: []string{"b", "b", "b.com"},
	}
	c := &ctx509.Certificate{
		Raw: []byte{1},
		Subject: pkix.Name{
			CommonName: "c",
		},
		DNSNames: []string{"c", "c", "c.com"},
	}
	d := &ctx509.Certificate{
		Raw: []byte{3},
		Subject: pkix.Name{
			CommonName: "d",
		},
		DNSNames: []string{"d", "d", "d.com"},
	}

	certs := []*ctx509.Certificate{
		a,
		b,
	}
	chains := [][]*ctx509.Certificate{
		nil,
		{c, d},
	}
	allCerts, IDs, parentIDs, names := UnfoldCerts(certs, chains)

	fmt.Printf("[%p %p %p %p]\n", a, b, c, d)
	fmt.Printf("%v\n", allCerts)
	fmt.Printf("%v\n", IDs)
	fmt.Printf("%v\n", parentIDs)

	assert.Len(t, allCerts, 4)
	assert.Len(t, IDs, 4)
	assert.Len(t, parentIDs, 4)

	// Check payloads.
	assert.Equal(t, a, allCerts[0])
	assert.Equal(t, b, allCerts[1])
	assert.Equal(t, c, allCerts[2])
	assert.Equal(t, d, allCerts[3])

	// Check IDs.
	aID := common.SHA256Hash32Bytes(a.Raw)
	bID := common.SHA256Hash32Bytes(b.Raw)
	cID := common.SHA256Hash32Bytes(c.Raw)
	dID := common.SHA256Hash32Bytes(d.Raw)

	assert.Equal(t, aID, *IDs[0])
	assert.Equal(t, bID, *IDs[1])
	assert.Equal(t, cID, *IDs[2])
	assert.Equal(t, dID, *IDs[3])

	// Check parent IDs.
	nilID := (*common.SHA256Output)(nil)
	assert.Equal(t, nilID, parentIDs[0], "bad parent at 0")
	assert.Equal(t, cID, *parentIDs[1], "bad parent at 1")
	assert.Equal(t, dID, *parentIDs[2], "bad parent at 2")
	assert.Equal(t, nilID, parentIDs[3], "bad parent at 3")

	// Check domain names.
	nilNames := ([]string)(nil)
	assert.ElementsMatch(t, []string{"a", "a.com"}, names[0]) // root but also a leaf
	assert.ElementsMatch(t, []string{"b", "b.com"}, names[1]) // just a leaf
	assert.Equal(t, nilNames, names[2])                       // not a leaf
	assert.Equal(t, nilNames, names[3])                       // not a leaf
}
