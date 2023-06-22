package crypto_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestSignatureOfRCSR: Generate RCSR -> generate signature for RCSR -> verify signature
func TestSignatureOfRCSR(t *testing.T) {
	privKey, err := util.RSAKeyFromPEMFile("./testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")

	pubKeyBytes, err := util.RSAPublicToPEM(&privKey.PublicKey)
	require.NoError(t, err, "RSA key to bytes error")
	test := random.RandomPolCertSignRequest(t)
	test.PublicKey = pubKeyBytes

	err = crypto.SignAsOwner(privKey, test)
	require.NoError(t, err, "RCSR sign signature error")

	err = crypto.VerifyOwnerSignature(test)
	require.NoError(t, err, "RCSR verify signature error")
}

// TestIssuanceOfRPC:  check if the CA signature is correct
func TestIssuanceOfRPC(t *testing.T) {
	// Phase 1: domain owner generates a policy certificate signing request.
	privKey, err := util.RSAKeyFromPEMFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")
	pubKeyBytes, err := util.RSAPublicToPEM(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")
	req := random.RandomPolCertSignRequest(t)
	req.PublicKey = pubKeyBytes
	// generate signature for request
	err = crypto.SignAsOwner(privKey, req)
	require.NoError(t, err, "RCSR Create Signature error")

	// Phase 2: pca issues policy certificate.
	err = crypto.VerifyOwnerSignature(req)
	// Validate the signature in rcsr
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := util.RSAKeyFromPEMFile("./testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := crypto.SignAsIssuer(req, pcaPrivKey)
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------

	caCert, err := util.CertificateFromPEMFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509 Cert From File error")

	err = crypto.VerifyIssuerSignature(caCert, rpc)
	require.NoError(t, err, "RPC Verify CA Signature error")
}

// TestIssuanceOfPC: generate PC -> domain owner generate signature -> pca verify signature -> pca sign PC -> domain owner verifies PC
func TestIssuanceOfSP(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := util.RSAKeyFromPEMFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	pubKeyBytes, err := util.RSAPublicToPEM(&privKey.PublicKey)
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
	err = crypto.VerifyOwnerSignature(req)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := util.RSAKeyFromPEMFile("./testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := crypto.SignAsIssuer(req, pcaPrivKey)
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")
}
