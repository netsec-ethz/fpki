package pca

// for future use
// Testing of PCA is in the integration test, because it also need the help of domain owner.
// This file will be used for future logics.
import (
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Test_Config: do nothing
func TestNewPCA(t *testing.T) {
	_, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")
}

func TestCreateConfig(t *testing.T) {
	t.Skip("Not creating config")
	issuerKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/serverkey.pem")
	require.NoError(t, err)
	derKey, err := util.RSAPublicToDERBytes(&issuerKey.PublicKey)
	require.NoError(t, err)

	req := common.NewPolicyCertificateSigningRequest(
		0,
		"pca root policy certificate",
		"pca root policy certificate",
		13,
		"fpki.com",
		util.TimeFromSecs(10),
		util.TimeFromSecs(10000),
		true,
		derKey,
		common.RSA,
		common.SHA256,
		util.TimeFromSecs(1),
		common.PolicyAttributes{
			TrustedCA:         []string{"pca"},
			AllowedSubdomains: []string{""},
		},
		nil, // no owner signature
		nil, // hash of owner's public key
	)
	// Self sign this pol cert.
	rootPolCert, err := crypto.SignRequestAsIssuer(req, issuerKey)
	require.NoError(t, err)
	// And serialize it to file to include it in the configuration of the PCA.
	err = common.ToJSONFile(rootPolCert, "testdata/rpc.json")
	require.NoError(t, err)

	c := &PCAConfig{
		CAName:             "pca",
		KeyPath:            "../../tests/testdata/serverkey.pem",
		RootPolicyCertPath: "testdata/rpc.json",
		CTLogServers: []CTLogServerEntryConfig{
			{
				Name:         "CT log server 1",
				URL:          "URL1.com/foo/bar1",
				PublicKeyDER: derKey,
			},
			{
				Name:         "CT log server 2",
				URL:          "URL2.com/foo/bar2",
				PublicKeyDER: derKey,
			},
		},
	}
	err = SaveConfigToFile(c, "testdata/pca_config.json")
	require.NoError(t, err)
}
func TestPCAWorkflow(t *testing.T) {
	pca, err := NewPCA("testdata/pca_config.json")
	require.NoError(t, err, "New PCA error")
	// pca is configured using pca_config.json, which itself specifies the PCA to use serverkey.pem
	// as the key to use to issue policy certificates.
	notBefore := util.TimeFromSecs(10 + 1)
	notAfter := util.TimeFromSecs(10000 - 10)
	// The requester needs a key (which will be identified in the request itself).
	ownerKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/clientkey.pem")
	require.NoError(t, err)
	ownerDerKey, err := util.RSAPublicToDERBytes(&ownerKey.PublicKey)
	require.NoError(t, err)
	// The workflow from the PCA's perspective is as follows:
	// 1. Create request
	req, err := pca.NewPolicyCertificateSigningRequest(
		1,
		"fpki.com",
		1,
		"fpki.com",
		notBefore,
		notAfter,
		true,
		ownerDerKey, // public key
		common.RSA,
		common.SHA256,
		common.PolicyAttributes{}, // policy attributes
		func(serialized []byte) []byte {
			return nil
		},
		common.SHA256Hash(ownerDerKey), // owner pub key hash
	)
	require.NoError(t, err)

	// 2. Owner signs request
	pca.increaseSerialNumber()
	err = crypto.SignAsOwner(ownerKey, req)
	require.NoError(t, err)

	// 3. PCA verifies owner's signature
	skip, err := pca.canSkipCoolOffPeriod(req)
	require.NoError(t, err)
	require.False(t, skip) // because the PCA doesn't contain the pol cert used to sign it.

	// 4. PCA signs as issuer
	pc, err := pca.signRequest(req)
	require.NoError(t, err)

	// 5. PCA sends to log servers. Per log server:
	mockRequester := newmockLogServerRequester(t, pca.CtLogServers)
	pca.LogServerRequester = mockRequester
	// 		6. Log server verifies CA signature.
	// 		7. Creates and returns its SPT
	// 		8. PCA adds SPT to list in policy certificate
	err = pca.sendRequestToAllLogServers(pc)
	require.NoError(t, err)
	require.Len(t, pc.SPCTs, len(pca.CtLogServers)) // as many SPTs as CT log servers
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
	require.Len(t, pca.DB, 1)
	for certID, cert := range pca.DB {
		// The ID is correct:
		require.Equal(t, certID, [32]byte(common.SHA256Hash32Bytes(pc.PublicKey)))
		// And the DB contains the correct pol cert.
		require.Equal(t, pc, cert)
		break
	}
}

// mockLogServerRequester mocks a CT log server requester.
type mockLogServerRequester struct {
	servers map[string]*CTLogServerEntryConfig
	pcaCert *ctx509.Certificate
	keys    map[string]*rsa.PrivateKey

	// URLs of the called CT log servers when sending the final policy cert.
	finalPolCertSentTo []string
}

func newmockLogServerRequester(t tests.T, servers map[[32]byte]*CTLogServerEntryConfig) *mockLogServerRequester {
	// Load the certificate of the PCA.
	pcaCert, err := util.CertificateFromPEMFile("../../tests/testdata/servercert.pem")
	require.NoError(t, err)

	// Load the keys of the CT log servers. This mock requester uses one for all of them.
	ctKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/serverkey.pem")
	require.NoError(t, err)

	m := make(map[string]*CTLogServerEntryConfig)
	keys := make(map[string]*rsa.PrivateKey)
	for _, s := range servers {
		s := s
		m[s.URL] = s
		keys[s.URL] = ctKey
	}

	return &mockLogServerRequester{
		servers:            m,
		pcaCert:            pcaCert,
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
	logID := common.SHA256Hash(m.servers[url].PublicKeyDER)
	spt := common.NewSignedPolicyCertificateTimestamp(
		0,
		pc.Issuer,
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

	ctKey, err := util.RSAKeyFromPEMFile("../../tests/testdata/serverkey.pem")
	require.NoError(t, err)
	derKey, err := util.RSAPublicToDERBytes(&ctKey.PublicKey)
	require.NoError(t, err)
	hashedDerKey := common.SHA256Hash(derKey)

	for _, spt := range pc.SPCTs {
		require.Equal(t, hashedDerKey, spt.LogID)
		require.Equal(t, pca.RootPolicyCert.Subject(), spt.Issuer)
		require.Less(t, time.Since(spt.AddedTS), time.Minute)
		require.Greater(t, time.Since(spt.AddedTS).Seconds(), 0.0)
	}
}
