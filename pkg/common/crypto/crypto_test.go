package crypto_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
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
	test := common.NewRCSR("this is a test",
		44,
		time.Now(),
		common.RSA,
		pubKeyBytes,
		common.SHA256,
		random.RandomBytesForTest(t, 32),
		random.RandomBytesForTest(t, 32),
	)

	err = crypto.RCSRCreateSignature(privKey, test)
	require.NoError(t, err, "RCSR sign signature error")

	err = crypto.RCSRVerifySignature(test)
	require.NoError(t, err, "RCSR verify signature error")
}

// TestIssuanceOfRPC:  check if the CA signature is correct
func TestIssuanceOfRPC(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := util.RSAKeyFromPEMFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	pubKeyBytes, err := util.RSAPublicToPEM(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")
	rcsr := common.NewRCSR("this is a test",
		44,
		time.Now(),
		common.RSA,
		pubKeyBytes,
		common.SHA256,
		random.RandomBytesForTest(t, 32),
		random.RandomBytesForTest(t, 32),
	)

	// generate signature for rcsr
	err = crypto.RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = crypto.RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := util.RSAKeyFromPEMFile("./testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := crypto.RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------

	caCert, err := util.CertificateFromPEMFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509 Cert From File error")

	err = crypto.RPCVerifyCASignature(caCert, rpc)
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
	rcsr := common.NewRCSR("this is a test",
		44,
		time.Now(),
		common.RSA,
		pubKeyBytes,
		common.SHA256,
		random.RandomBytesForTest(t, 32),
		random.RandomBytesForTest(t, 32),
	)

	// generate signature for rcsr
	err = crypto.RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = crypto.RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := util.RSAKeyFromPEMFile("./testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := crypto.RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner generate SP
	// -------------------------------------
	psr := common.NewPSR(
		"test_SP",
		common.PolicyAttributes{},
		time.Now(),
		nil,
	)

	err = crypto.DomainOwnerSignPSR(privKey, psr)
	require.NoError(t, err, "DomainOwnerSignPSR error")

	// -------------------------------------
	//  phase 4: pca check psr
	// -------------------------------------
	err = crypto.VerifyPSRUsingRPC(psr, rpc)
	require.NoError(t, err, "VerifyPSRUsingRPC error")

	sp, err := crypto.CASignSP(psr, pcaPrivKey, "test ca", 22)
	require.NoError(t, err, "CASignSP error")

	// -------------------------------------
	//  phase 5: domain owner check sp
	// -------------------------------------
	caCert, err := util.CertificateFromPEMFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	err = crypto.VerifyCASigInSP(caCert, sp)
	require.NoError(t, err, "VerifyCASigInSP error")
}
