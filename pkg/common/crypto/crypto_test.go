package crypto_test

import (
	cryptolib "crypto"
	"crypto/rsa"
	"io/ioutil"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
)

var update = tests.UpdateGoldenFiles()

func TestUpdateGoldenFiles(t *testing.T) {
	rand.Seed(0)
	if !*update {
		t.Skip("Not updating golden files: flag not set")
	}
	t.Log("Updating policy certificate files for tests/testdata")
	// Obtain a new pair for the root issuer.
	issuerCert, issuerKey := randomPolCertAndKey(t)
	issuerCert.CanIssue = true
	issuerCert.CanOwn = true

	// Objain a new pair for the owner.
	ownerCert, ownerKey := randomPolCertAndKey(t)
	ownerCert.CanIssue = false
	ownerCert.CanOwn = true
	// The owner will be issued by the root issuer.
	err := crypto.SignPolicyCertificateAsIssuer(issuerCert, issuerKey, ownerCert)
	require.NoError(t, err)

	// Store all certs and keys. Filename -> payload.
	const (
		typeIssuerCert int = iota // Even numbers are certs
		typeIssuerKey             // Odd numbers are keys
		typeOwnerCert
		typeOwnerKey
	)
	filenames := map[int]string{
		typeIssuerCert: "../../../tests/testdata/issuer_cert.json",
		typeIssuerKey:  "../../../tests/testdata/issuer_key.pem",
		typeOwnerCert:  "../../../tests/testdata/owner_cert.json",
		typeOwnerKey:   "../../../tests/testdata/owner_key.pem",
	}

	payloads := make(map[int][]byte)
	// Issuer pair:
	data, err := util.PolicyCertificateToBytes(issuerCert)
	require.NoError(t, err)
	payloads[typeIssuerCert] = data
	payloads[typeIssuerKey] = util.RSAKeyToPEM(issuerKey)
	// Owner pair:
	data, err = util.PolicyCertificateToBytes(ownerCert)
	require.NoError(t, err)
	payloads[typeOwnerCert] = data
	payloads[typeOwnerKey] = util.RSAKeyToPEM(ownerKey)

	// Write all files.
	for _type, payload := range payloads {
		err = ioutil.WriteFile(filenames[_type], payload, 0666)
		require.NoError(t, err)
	}

	// For safety of these tests, check again the created files.
	expectedObjects := map[int]any{
		typeIssuerCert: issuerCert,
		typeIssuerKey:  issuerKey,
		typeOwnerCert:  ownerCert,
		typeOwnerKey:   ownerKey,
	}
	for _type, filename := range filenames {
		var gotObj any
		if _type%2 == 0 {
			gotObj, err = util.PolicyCertificateFromFile(filename)
			require.NoError(t, err)
		} else {
			gotObj, err = util.RSAKeyFromPEMFile(filename)
			require.NoError(t, err)
		}
		require.Equal(t, expectedObjects[_type], gotObj)
	}
}

func TestComputeHashAsOwner(t *testing.T) {
	rand.Seed(1)

	// Get random policy certificate and check it contains SPCTs, owner, and issuer fields.
	pc := random.RandomPolicyCertificate(t)
	require.NotEmpty(t, pc.SPCTs)
	require.NotEmpty(t, pc.OwnerSignature)
	require.NotEmpty(t, pc.OwnerHash)
	require.NotEmpty(t, pc.IssuerSignature)
	require.NotEmpty(t, pc.IssuerHash)

	gotHash, err := crypto.ComputeHashAsSigner(pc)
	require.NoError(t, err)

	// Remove SPCTs and issuer signature, and serialize.
	pc.SPCTs = nil
	pc.IssuerSignature = nil
	serializedPC, err := common.ToJSON(pc)
	require.NoError(t, err)

	// Compare with the expected value.
	expected := common.SHA256Hash(serializedPC)
	require.Equal(t, expected, gotHash)
}

func TestSignAsOwner(t *testing.T) {
	rand.Seed(11)

	// Load owner policy cert and key.
	ownerCert, err := util.PolicyCertificateFromFile("../../../tests/testdata/owner_cert.json")
	require.NoError(t, err)
	ownerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/owner_key.pem")
	require.NoError(t, err)

	// Create random request.
	request := random.RandomPolCertSignRequest(t)
	require.NotEmpty(t, request.OwnerSignature)
	require.NotEmpty(t, request.OwnerHash)
	request.CanIssue = true

	// Sign as owner.
	err = crypto.SignAsOwner(ownerCert, ownerKey, request)
	require.Error(t, err) // owner signature and hash not nil
	request.OwnerHash = nil
	err = crypto.SignAsOwner(ownerCert, ownerKey, request)
	require.Error(t, err) // owner hash not nil
	request.OwnerSignature = []byte{}
	err = crypto.SignAsOwner(ownerCert, ownerKey, request)
	require.Error(t, err) // owner hash empty but not nil
	request.OwnerSignature = nil
	// It should not fail now:
	err = crypto.SignAsOwner(ownerCert, ownerKey, request)
	require.NoError(t, err)
	require.NotEmpty(t, request.OwnerSignature)
	require.NotEmpty(t, request.OwnerHash)
	gotSignature := request.OwnerSignature

	// Manually do the steps to sign, and compare results. 3 stesps.
	// 1. Check the owner hash is correct.
	ownerHash, err := crypto.ComputeHashAsSigner(ownerCert)
	require.NoError(t, err)
	require.Equal(t, ownerHash, request.OwnerHash)
	// 2. Sign the child request without owner signature.
	request.OwnerSignature = nil
	serializedRequestWoutOwnerSignature, err := common.ToJSON(common.NewPolicyCertificateFromRequest(request))
	require.NoError(t, err)
	expectedSignature, err := crypto.SignStructRSASHA256(common.NewPolicyCertificateFromRequest(request), ownerKey)
	require.NoError(t, err)
	// 3. Compare signatures.
	require.Equal(t, expectedSignature, gotSignature)
	request.OwnerSignature = gotSignature

	// Check that the signature corresponds to the owner's key.
	err = rsa.VerifyPKCS1v15(&ownerKey.PublicKey, cryptolib.SHA256,
		common.SHA256Hash(serializedRequestWoutOwnerSignature), gotSignature)
	require.NoError(t, err)

	// Additionally check that our VerifyOwnerSignature works as expected.
	err = crypto.VerifyOwnerSignature(ownerCert, request)
	require.NoError(t, err)
}

func TestSignPolicyCertificateAsIssuer(t *testing.T) {
	rand.Seed(12)

	// Load issuer policy cert and key.
	issuerCert, err := util.PolicyCertificateFromFile("../../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)
	issuerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/issuer_key.pem")
	require.NoError(t, err)

	// Create random policy certificate.
	childPolCert := random.RandomPolicyCertificate(t)
	require.NotEmpty(t, childPolCert.SPCTs)
	require.NotEmpty(t, childPolCert.OwnerSignature)
	require.NotEmpty(t, childPolCert.OwnerHash)
	require.NotEmpty(t, childPolCert.IssuerSignature)
	require.NotEmpty(t, childPolCert.IssuerHash)

	// Issuer-sign it:
	err = crypto.SignPolicyCertificateAsIssuer(issuerCert, issuerKey, childPolCert)
	require.Error(t, err) // issuer signature and hash not nil
	childPolCert.IssuerSignature = nil
	err = crypto.SignPolicyCertificateAsIssuer(issuerCert, issuerKey, childPolCert)
	require.Error(t, err) // issuer hash not nil
	childPolCert.IssuerHash = []byte{}
	err = crypto.SignPolicyCertificateAsIssuer(issuerCert, issuerKey, childPolCert)
	require.Error(t, err) // issuer hash empty, but still not nil
	childPolCert.IssuerHash = nil
	// It has to work now:
	err = crypto.SignPolicyCertificateAsIssuer(issuerCert, issuerKey, childPolCert)
	require.NoError(t, err)
	gotSignature := childPolCert.IssuerSignature

	// Manually do the steps to sign, and compare results. 3 stesps.
	// 1. Check that the issuer hash is correct.
	// Check that the issuer hash is correct.
	issuerHash, err := crypto.ComputeHashAsSigner(issuerCert)
	require.NoError(t, err)
	require.Equal(t, issuerHash, childPolCert.IssuerHash)
	// 2. Sign the child policy certificate without issuer signature.
	childPolCert.IssuerSignature = nil
	expectedSignature, err := crypto.SignStructRSASHA256(childPolCert, issuerKey)
	require.NoError(t, err)
	serializedChildPolCertWoutOwnerSignature, err := common.ToJSON(childPolCert)
	require.NoError(t, err)
	// 3. Compare signatures.
	require.Equal(t, expectedSignature, gotSignature)
	childPolCert.IssuerSignature = gotSignature

	// Check that the signature corresponds to the owner's key.
	err = rsa.VerifyPKCS1v15(&issuerKey.PublicKey, cryptolib.SHA256,
		common.SHA256Hash(serializedChildPolCertWoutOwnerSignature), gotSignature)
	require.NoError(t, err)

	// Additionally check that our VerifyIssuerSignature works as expected.
	err = crypto.VerifyIssuerSignature(issuerCert, childPolCert)
	require.NoError(t, err)
}

func TestSignRequestAsIssuer(t *testing.T) {
	rand.Seed(13)

	// Load issuer policy cert and key.
	issuerCert, err := util.PolicyCertificateFromFile("../../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)
	issuerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/issuer_key.pem")
	require.NoError(t, err)

	// Load owner policy cert and key.
	ownerCert, err := util.PolicyCertificateFromFile("../../../tests/testdata/owner_cert.json")
	require.NoError(t, err)
	ownerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/owner_key.pem")
	require.NoError(t, err)

	// Create random request.
	request := random.RandomPolCertSignRequest(t)
	request.OwnerHash = nil
	request.OwnerSignature = nil

	// Owner-sign it.
	err = crypto.SignAsOwner(ownerCert, ownerKey, request)
	require.NoError(t, err)

	// Issuer-sign the request.
	childPolCert, err := crypto.SignRequestAsIssuer(issuerCert, issuerKey, request)
	require.NoError(t, err)

	// Verify both owner and issuer.
	err = crypto.VerifyOwnerSignature(ownerCert, request)
	require.NoError(t, err)
	err = crypto.VerifyOwnerSignatureInPolicyCertificate(ownerCert, childPolCert)
	require.NoError(t, err)
	err = crypto.VerifyIssuerSignature(issuerCert, childPolCert)
	require.NoError(t, err)
}

func randomPolCertAndKey(t tests.T) (*common.PolicyCertificate, *rsa.PrivateKey) {
	cert := random.RandomPolicyCertificate(t)
	key := random.RandomRSAPrivateKey(t)

	// DER encoded public key.
	derPubKey, err := util.RSAPublicToDERBytes(&key.PublicKey)
	require.NoError(t, err)

	// Set the public key.
	cert.PublicKey = derPubKey

	// Set validity times between unix time 1 and 10000
	cert.NotBefore = util.TimeFromSecs(1)
	cert.NotAfter = util.TimeFromSecs(10000)

	// Remove signature and hash for owner and issuer.
	cert.OwnerSignature = nil
	cert.OwnerHash = nil
	cert.IssuerSignature = nil
	cert.IssuerHash = nil

	return cert, key
}
