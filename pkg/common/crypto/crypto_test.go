package crypto_test

import (
	libcrypto "crypto"
	"crypto/rsa"
	"testing"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func TestSignatureOfPolicyCertSignRequest(t *testing.T) {
	ownerPriv, err := util.RSAKeyFromPEMFile("../../../tests/testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")

	request := random.RandomPolCertSignRequest(t)
	request.IsIssuer = true

	// Sign as owner.
	err = crypto.SignAsOwner(ownerPriv, request)
	require.NoError(t, err, "RCSR sign signature error")

	// Serialize the request (w/out signature) to bytes to later check its hash value.
	sig := request.OwnerSignature
	request.OwnerSignature = nil
	serializedRequest, err := common.ToJSON(request)
	require.NoError(t, err)
	request.OwnerSignature = sig

	// Check that the signature corresponds to the owner's key.
	err = rsa.VerifyPKCS1v15(&ownerPriv.PublicKey, libcrypto.SHA256,
		common.SHA256Hash(serializedRequest), request.OwnerSignature)
	require.NoError(t, err)

	// Check that we have the hash of the public key of the owner's key.
	// The bytes of the public key have to be obtained via a call to ctx509.MarshalPKIXPublicKey
	pubKeyBytes, err := ctx509.MarshalPKIXPublicKey(&ownerPriv.PublicKey)
	require.NoError(t, err)
	require.Equal(t, common.SHA256Hash(pubKeyBytes), request.OwnerPubKeyHash)

	// Also check that our VerifyOwnerSignature works as expected.
	err = crypto.VerifyOwnerSignature(request, &ownerPriv.PublicKey)
	require.NoError(t, err, "RCSR verify signature error")
}

// TestIssuanceOfRPC:  check if the CA signature is correct
func TestSignAsIssuer(t *testing.T) {
	// Load crypto material for owner and issuer.
	ownerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/clientkey.pem")
	require.NoError(t, err)
	issuerKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/serverkey.pem")
	require.NoError(t, err)
	issuerCert, err := util.CertificateFromPEMFile("../../../tests/testdata/servercert.pem")
	require.NoError(t, err, "X509 Cert From File error")

	// Phase 1: domain owner generates a policy certificate signing request.
	req := random.RandomPolCertSignRequest(t)
	// generate signature for request
	err = crypto.SignAsOwner(ownerKey, req)
	require.NoError(t, err)

	// Phase 2: pca issues policy certificate.
	// we can validate the signature in the request, but in this test we know it's correct.
	err = crypto.VerifyOwnerSignature(req, &ownerKey.PublicKey)
	require.NoError(t, err, "RCSR Verify Signature error")
	// Sign as issuer.
	polCert, err := crypto.SignRequestAsIssuer(req, issuerKey)
	require.NoError(t, err, "RCSR Generate RPC error")
	assert.Equal(t, len(polCert.SPCTs), 0, "SPTs must be empty right after first issuer signature")

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------
	err = crypto.VerifyIssuerSignature(issuerCert, polCert)
	require.NoError(t, err, "RPC Verify CA Signature error")
}

// TestIssuanceOfPC: generate PC -> domain owner generate signature -> pca verify signature -> pca sign PC -> domain owner verifies PC
func TestIssuanceOfSP(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	// pubKeyBytes, err := util.RSAPublicToPEM(&privKey.PublicKey)
	// require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")
	pubKeyBytes, err := util.RSAPublicToDERBytes(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")

	req := random.RandomPolCertSignRequest(t)
	req.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = crypto.SignAsOwner(privKey, req)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = crypto.VerifyOwnerSignature(req, &privKey.PublicKey)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := util.RSAKeyFromPEMFile("../../../tests/testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := crypto.SignRequestAsIssuer(req, pcaPrivKey)
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPCTs), 0, "spt in the rpc should be empty")
}
