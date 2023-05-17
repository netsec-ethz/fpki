package common

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignatureOfRCSR: Generate RCSR -> generate signature for RCSR -> verify signature
func TestSignatureOfRCSR(t *testing.T) {
	privKey, err := LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")

	test := &RCSR{
		PolicyObjectBase: PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	pubKeyBytes, err := RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "RSA key to bytes error")

	test.PublicKey = pubKeyBytes

	err = RCSRCreateSignature(privKey, test)
	require.NoError(t, err, "RCSR sign signature error")

	err = RCSRVerifySignature(test)
	require.NoError(t, err, "RCSR verify signature error")
}

// TestIssuanceOfRPC:  check if the CA signature is correct
func TestIssuanceOfRPC(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	rcsr := &RCSR{
		PolicyObjectBase: PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	// add public key
	pubKeyBytes, err := RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")

	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := LoadRSAPrivateKeyFromFile("./testdata/serverkey.pem")
	rpc, err := RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner check rpc
	// -------------------------------------

	caCert, err := X509CertFromFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509 Cert From File error")

	err = RPCVerifyCASignature(caCert, rpc)
	require.NoError(t, err, "RPC Verify CA Signature error")
}

// TestIssuanceOfPC: generate PC -> domain owner generate signature -> pca verify signature -> pca sign PC -> domain owner verifies PC
func TestIssuanceOfSP(t *testing.T) {
	// -------------------------------------
	//  phase 1: domain owner generate rcsr
	// -------------------------------------
	privKey, err := LoadRSAPrivateKeyFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	rcsr := &RCSR{
		PolicyObjectBase: PolicyObjectBase{
			Subject: "this is a test",
		},
		Version:            44,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
	}

	// add public key
	pubKeyBytes, err := RsaPublicKeyToPemBytes(&privKey.PublicKey)
	require.NoError(t, err, "Rsa PublicKey To Pem Bytes error")

	rcsr.PublicKey = pubKeyBytes

	// generate signature for rcsr
	err = RCSRCreateSignature(privKey, rcsr)
	require.NoError(t, err, "RCSR Create Signature error")

	// -------------------------------------
	//  phase 2: pca issue rpc
	// -------------------------------------
	// validate the signature in rcsr
	err = RCSRVerifySignature(rcsr)
	require.NoError(t, err, "RCSR Verify Signature error")

	pcaPrivKey, err := LoadRSAPrivateKeyFromFile("./testdata/serverkey.pem")
	rpc, err := RCSRGenerateRPC(rcsr, time.Now(), 1, pcaPrivKey, "fpki")
	require.NoError(t, err, "RCSR Generate RPC error")

	assert.Equal(t, len(rpc.SPTs), 0, "spt in the rpc should be empty")

	// -------------------------------------
	//  phase 3: domain owner generate SP
	// -------------------------------------
	psr := &PSR{
		TimeStamp:  time.Now(),
		DomainName: "test_SP",
	}

	err = DomainOwnerSignPSR(privKey, psr)
	require.NoError(t, err, "DomainOwnerSignPSR error")

	// -------------------------------------
	//  phase 4: pca check psr
	// -------------------------------------
	err = VerifyPSRUsingRPC(psr, rpc)
	require.NoError(t, err, "VerifyPSRUsingRPC error")

	sp, err := CASignSP(psr, pcaPrivKey, "test ca", 22)
	require.NoError(t, err, "CASignSP error")

	// -------------------------------------
	//  phase 5: domain owner check sp
	// -------------------------------------
	caCert, err := X509CertFromFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	err = VerifyCASigInSP(caCert, sp)
	require.NoError(t, err, "VerifyCASigInSP error")
}

// -------------------------------------------------------------
//
//	funcs for testing
//
// -------------------------------------------------------------
func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
