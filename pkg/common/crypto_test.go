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
	privKey, err := LoadRSAKeyPairFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "load RSA key error")

	test := &RCSR{
		Subject:            "this is a test",
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
	privKey, err := LoadRSAKeyPairFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	rcsr := &RCSR{
		Subject:            "this is a test",
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

	pcaPrivKey, err := LoadRSAKeyPairFromFile("./testdata/serverkey.pem")
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
func TestIssuanceOfPC(t *testing.T) {
	privKey, err := LoadRSAKeyPairFromFile("./testdata/clientkey.pem")
	require.NoError(t, err, "Load RSA Key Pair From File error")

	pc := PC{
		Policies: []Policy{
			{
				TrustedCA: []string{
					"hihihih", "I'm the test",
				},
			},
		},
		Subject: "test domain",
	}

	err = DomainOwnerSignPC(privKey, &pc)
	require.NoError(t, err, "DomainOwnerSignPC error")

	pcaPrivKey, err := LoadRSAKeyPairFromFile("./testdata/serverkey.pem")
	require.NoError(t, err, "LoadRSAKeyPairFromFile error")

	domainRPC, err := X509CertFromFile("./testdata/clientcert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	signedPC, err := CAVefiryPCAndSign(domainRPC, pc, pcaPrivKey, "pca", 16)
	require.NoError(t, err, "CAVefiryPCAndSign error")

	pcaCert, err := X509CertFromFile("./testdata/servercert.pem")
	require.NoError(t, err, "X509CertFromFile error")

	err = VerifyCASigInPC(pcaCert, signedPC)
	require.NoError(t, err, "VerifyCASigInPC error")
}

//-------------------------------------------------------------
//                    funcs for testing
//-------------------------------------------------------------
func generateRandomBytes() []byte {
	token := make([]byte, 40)
	rand.Read(token)
	return token
}

func generateRandomBytesArray() [][]byte {
	return [][]byte{generateRandomBytes()}
}
