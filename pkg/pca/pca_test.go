package pca

// for future use
// Testing of PCA is in the integration test, because it also need the help of domain owner.
// This file will be used for future logics.
import (
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
)

var updateGolden = tests.UpdateGoldenFiles()

// Test_Config: do nothing
func TestNewPCA(t *testing.T) {
	_, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")
}

func TestUpdateGoldenFiles(t *testing.T) {
	if !*updateGolden {
		t.Skip("Not creating config")
	}

	// Read the files containing the cert and key.
	certJSON, err := os.ReadFile("../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)
	keyPEM, err := os.ReadFile("../../tests/testdata/issuer_key.pem")
	require.NoError(t, err)

	// Instantiate the certificate.
	cert, err := util.PolicyCertificateFromBytes(certJSON)
	require.NoError(t, err)

	c := &PCAConfig{
		CAName:   "pca",
		CertJSON: certJSON,
		KeyPEM:   keyPEM,
		CTLogServers: []CTLogServerEntryConfig{
			{
				Name:         "CT log server 1",
				URL:          "URL1.com/foo/bar1",
				PublicKeyDER: cert.PublicKey,
			},
			{
				Name:         "CT log server 2",
				URL:          "URL2.com/foo/bar2",
				PublicKeyDER: cert.PublicKey,
			},
		},
	}
	err = SaveConfigToFile(c, "testdata/pca_config.json")
	require.NoError(t, err)
}

// TestPCAWorkflow checks that the PCA workflow works as intended.
func TestPCAWorkflow(t *testing.T) {
	pca, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")

	// The requester needs a key (which will be identified in the request itself).
	ownerKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/owner_key.pem")
	require.NoError(t, err)
	ownerCert, err := util.PolicyCertificateFromFile("../../tests/testdata/owner_cert.json")
	require.NoError(t, err)
	ownerHash, err := crypto.ComputeHashAsSigner(ownerCert)
	require.NoError(t, err)

	signingFunctionCallTimes := 0 // incremented when the owner is requested to sign
	// The workflow from the PCA's perspective is as follows:
	// 1. Create request.
	notBefore := pca.RootPolicyCert.NotBefore.Add(-1) // this will be invalid at first
	notAfter := pca.RootPolicyCert.NotAfter.Add(1)    // this will be invalid at first
	create := func() (*common.PolicyCertificateSigningRequest, error) {
		return pca.NewPolicyCertificateSigningRequest(
			1,
			"fpki.com",
			notBefore,
			notAfter,
			true,
			ownerCert.PublicKey, // public key
			common.RSA,
			common.SHA256,
			common.PolicyAttributes{}, // policy attributes
			func(serialized []byte) []byte {
				signingFunctionCallTimes++
				data, err := crypto.SignBytes(serialized, ownerKey)
				require.NoError(t, err)
				return data
			},
			ownerHash, // owner hash
		)
	}
	_, err = create()
	require.Error(t, err) // not before is too early
	notBefore = pca.RootPolicyCert.NotBefore.Add(1)
	_, err = create()
	require.Error(t, err) // not after is too late
	notAfter = pca.RootPolicyCert.NotAfter.Add(-1)
	// It shouldn't fail now.
	req, err := create()
	require.NoError(t, err)

	// 2. Owner has signed the request. We can verify this.
	require.Equal(t, 1, signingFunctionCallTimes)
	// Check the signature.
	err = crypto.VerifyOwnerSignature(ownerCert, req)
	require.NoError(t, err)

	// 3. PCA verifies owner's signature
	skip, err := pca.canSkipCoolOffPeriod(req)
	require.NoError(t, err)
	require.False(t, skip) // because the PCA doesn't contain the pol cert used to sign it.
	// Let's add the root policy certificate that owner-signed the child pol cert.
	pca.DB[*(*[32]byte)(ownerHash)] = ownerCert
	skip, err = pca.canSkipCoolOffPeriod(req)
	require.NoError(t, err)
	require.True(t, skip)
	// For the test, remove the root pol cert from the DB.
	delete(pca.DB, *(*[32]byte)(ownerHash))

	// 4. PCA signs as issuer
	pc, err := pca.signRequest(req)
	require.NoError(t, err)
	// Verify PCA's signature.
	err = crypto.VerifyIssuerSignature(pca.RootPolicyCert, pc)
	require.NoError(t, err)

	// 5. PCA sends to log servers. Per log server:
	mockRequester := newmockLogServerRequester(t, pca.CtLogServers)
	pca.LogServerRequester = mockRequester
	// 		6. Log server verifies CA signature.
	// 		7. Creates and returns its SPT
	// 		8. PCA adds SPT to list in policy certificate
	err = pca.sendRequestToAllLogServers(pc)
	require.NoError(t, err)
	require.Equal(t, len(pca.CtLogServers), len(pc.SPCTs)) // as many SPTs as CT log servers
	checkSPTs(t, pca, pc)

	// 9. PCA signs again the policy certificate
	err = pca.signFinalPolicyCertificate(pc)
	require.NoError(t, err)

	// 10. PCA sends the policy certificate to all log servers.
	err = pca.sendFinalPolCertToAllLogServers(pc)
	require.NoError(t, err)
	expectedURLs := make([]string, 0)
	for _, e := range pca.CtLogServers {
		expectedURLs = append(expectedURLs, e.URL)
	}
	require.ElementsMatch(t, expectedURLs, mockRequester.finalPolCertSentTo)

	// 11. PCA stores the final policy certificate in its DB.
	pca.storeInDb(pc)
	require.Equal(t, 1, len(pca.DB))
	for certID, cert := range pca.DB {
		// The ID is correct:
		require.Equal(t, certID, [32]byte(common.SHA256Hash32Bytes(pc.PublicKey)))
		// And the DB contains the correct pol cert.
		require.Equal(t, pc, cert)
		break
	}
}

func TestSignAndLogRequest(t *testing.T) {
	pca, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")

	// The requester needs a key (which will be identified in the request itself).
	ownerKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/owner_key.pem")
	require.NoError(t, err)
	ownerCert, err := util.PolicyCertificateFromFile("../../tests/testdata/owner_cert.json")
	require.NoError(t, err)
	ownerHash, err := crypto.ComputeHashAsSigner(ownerCert)
	require.NoError(t, err)

	// Let's add the root policy certificate from the owner.
	pca.DB[*(*[32]byte)(ownerHash)] = ownerCert

	req, err := pca.NewPolicyCertificateSigningRequest(
		1,
		"fpki.com",
		pca.RootPolicyCert.NotBefore,
		pca.RootPolicyCert.NotAfter,
		true,
		ownerCert.PublicKey, // public key
		common.RSA,
		common.SHA256,
		common.PolicyAttributes{}, // policy attributes
		func(serialized []byte) []byte {
			data, err := crypto.SignBytes(serialized, ownerKey)
			require.NoError(t, err)
			return data
		},
		ownerHash, // owner hash
	)
	require.NoError(t, err)

	// Before we call the regular function, we must have a LogServerRequester
	mockRequester := newmockLogServerRequester(t, pca.CtLogServers)
	pca.LogServerRequester = mockRequester

	// Call the regular function.
	pc, err := pca.SignAndLogRequest(req)
	require.NoError(t, err)

	// Check we have as many SPTs as CT log servers.
	require.Equal(t, len(pca.CtLogServers), len(pc.SPCTs))
	// And check the SPTs themselves.
	checkSPTs(t, pca, pc)

	// Check we made the correct calls to the CT log servers.
	expectedURLs := make([]string, 0)
	for _, e := range pca.CtLogServers {
		expectedURLs = append(expectedURLs, e.URL)
	}
	require.ElementsMatch(t, expectedURLs, mockRequester.finalPolCertSentTo)

	// Check that the PCA stored the policy certificate.
	require.Equal(t, 2, len(pca.DB)) // owner root pol cert plus the new one.

	// For the test, remove the root pol cert from the DB.
	delete(pca.DB, *(*[32]byte)(ownerHash))

	// Verify that the remainig one is the child certificate.
	for certID, cert := range pca.DB {
		// The ID is correct:
		require.Equal(t, certID, [32]byte(common.SHA256Hash32Bytes(pc.PublicKey)))
		// And the DB contains the correct pol cert.
		require.Equal(t, pc, cert)
		break
	}

	// Verify owner's signature still valid.
	err = crypto.VerifyOwnerSignatureInPolicyCertificate(ownerCert, pc)
	require.NoError(t, err)

	// Verify PCA's signature.
	err = crypto.VerifyIssuerSignature(pca.RootPolicyCert, pc)
	require.NoError(t, err)
}

// mockLogServerRequester mocks a CT log server requester.
type mockLogServerRequester struct {
	ctLogServers map[string]*CTLogServerEntryConfig
	pcaCert      *common.PolicyCertificate

	// Cert-Key pair per domain:
	certs map[string]*common.PolicyCertificate
	keys  map[string]*rsa.PrivateKey

	// URLs of the called CT log servers when sending the final policy cert.
	finalPolCertSentTo []string
}

func newmockLogServerRequester(
	t tests.T,
	servers map[[32]byte]*CTLogServerEntryConfig,
) *mockLogServerRequester {

	// Load the certificate of the PCA.
	pcaCert, err := util.PolicyCertificateFromFile("../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)

	// Load the policy certificates and keys of the CT log servers. This mock requester
	// uses one pair for all of them.
	ctCert, err := util.PolicyCertificateFromFile("../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)
	ctKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/issuer_key.pem")
	require.NoError(t, err)

	m := make(map[string]*CTLogServerEntryConfig)
	certs := make(map[string]*common.PolicyCertificate)
	keys := make(map[string]*rsa.PrivateKey)
	for _, s := range servers {
		s := s
		m[s.URL] = s
		certs[s.URL] = ctCert
		keys[s.URL] = ctKey
	}

	return &mockLogServerRequester{
		ctLogServers:       m,
		pcaCert:            pcaCert,
		certs:              certs,
		keys:               keys,
		finalPolCertSentTo: make([]string, 0),
	}
}

func (m *mockLogServerRequester) ObtainSptFromLogServer(
	url string,
	pc *common.PolicyCertificate,
) (*common.SignedPolicyCertificateTimestamp, error) {

	// Step 6 verify PCA signature.
	if err := crypto.VerifyIssuerSignature(m.pcaCert, pc); err != nil {
		return nil, err
	}
	serializedPc, err := common.ToJSON(pc)
	if err != nil {
		return nil, err
	}

	// Step 7 create and add SPT.
	signature, err := crypto.SignBytes(serializedPc, m.keys[url])
	if err != nil {
		return nil, fmt.Errorf("error signing: %w", err)
	}
	logID := common.SHA256Hash(m.ctLogServers[url].PublicKeyDER)
	spt := common.NewSignedPolicyCertificateTimestamp(
		0,
		logID,
		time.Now(),
		signature,
	)
	return spt, nil
}

func (m *mockLogServerRequester) SendPolicyCertificateToLogServer(
	url string,
	pc *common.PolicyCertificate,
) error {

	// We only annotate to whom the PCA called.
	m.finalPolCertSentTo = append(m.finalPolCertSentTo, url)
	return nil
}

// checkSPTs checks that the SPTs inside the policy certificate are the expected ones.
func checkSPTs(t tests.T, pca *PCA, pc *common.PolicyCertificate) {
	t.Helper()

	ctCert, err := util.PolicyCertificateFromFile("../../tests/testdata/issuer_cert.json")
	require.NoError(t, err)

	// ctKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/serverkey.pem")
	// require.NoError(t, err)
	// derKey, err := util.RSAPublicToDERBytes(&ctKey.PublicKey)
	// require.NoError(t, err)
	hashedDerKey := common.SHA256Hash(ctCert.PublicKey)

	for _, spt := range pc.SPCTs {
		require.Equal(t, hashedDerKey, spt.LogID)
		require.Less(t, time.Since(spt.AddedTS), time.Minute)
		require.Greater(t, time.Since(spt.AddedTS).Seconds(), 0.0)
		// TODO check spt.Signature
	}
}
