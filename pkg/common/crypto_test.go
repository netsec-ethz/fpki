package common_test

import (
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignatureOfRCSR: Generate RCSR -> generate signature for RCSR -> verify signature
func TestSignatureOfRCSR(t *testing.T) {
	privKey, err := common.LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")

	test := &common.RCSR{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       random.RandomBytesForTest(t, 32),
		Signature:          random.RandomBytesForTest(t, 32),
	}

	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "RSA key to bytes error")

	test.PublicKey = pubKeyBytes

	err = common.RCSRCreateSignature(privKey, test)
	require.NoError(t, err, "RCSR sign signature error")

	err = common.RCSRVerifySignature(test)
	require.NoError(t, err, "RCSR verify signature error")
}

// TestIssuanceOfRPC:  check if the CA signature is correct
func TestIssuanceOfRPC(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := common.LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	rcsr := &common.RCSR{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       random.RandomBytesForTest(t, 32),
		Signature:          random.RandomBytesForTest(t, 32),
	}

	// add public key
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")

	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = common.RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = common.RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := common.LoadRSAPrivateKeyFromFile("./testdata/serverkey.pem")
	rpc, err := common.RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------

	caCert, err := util.CertificateFromPEMFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509 Cert From File error")

	err = common.RPCVerifyCASignature(caCert, rpc)
	require.NoError(t, err, "RPC Verify CA Signature error")
}

// TestIssuanceOfPC: generate PC -> domain owner generate signature -> pca verify signature -> pca sign PC -> domain owner verifies PC
func TestIssuanceOfSP(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := common.LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	rcsr := &common.RCSR{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       random.RandomBytesForTest(t, 32),
	}

	// add public key
	pubKeyBytes, err := common.RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")

	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = common.RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = common.RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := common.LoadRSAPrivateKeyFromFile("./testdata/serverkey.pem")
	require.NoError(t, err)
	rpc, err := common.RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner generate SP
	// -------------------------------------
	psr := &common.PSR{
		TimeStamp:  time.Now(),
		DomainName: "test_SP",
	}

	err = common.DomainOwnerSignPSR(privKey, psr)
	require.NoError(t, err, "DomainOwnerSignPSR error")

	// -------------------------------------
	//  phase 4: pca check psr
	// -------------------------------------
	err = common.VerifyPSRUsingRPC(psr, rpc)
	require.NoError(t, err, "VerifyPSRUsingRPC error")

	sp, err := common.CASignSP(psr, pcaPrivKey, "test ca", 22)
	require.NoError(t, err, "CASignSP error")

	// -------------------------------------
	//  phase 5: domain owner check sp
	// -------------------------------------
	caCert, err := util.CertificateFromPEMFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	err = common.VerifyCASigInSP(caCert, sp)
	require.NoError(t, err, "VerifyCASigInSP error")
}
