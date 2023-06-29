package pca

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/common/crypto"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TODO(yongzhe):
//       How to handle Cool-off period?
//       SuspiciousSPTs
//       Let domain owner sends the previous RPC (PCA needs to store the RPC anyway, right?
//           If domain owner loses the RPC, PCA can return the missing RPC)
//       More complete logic

// PCA represents a policy certificate authority.
type PCA struct {
	CAName             string
	RsaKeyPair         *rsa.PrivateKey                        // PCA's signing key pair
	RootPolicyCert     *common.PolicyCertificate              // The PCA's policy certificate
	CtLogServers       map[[32]byte]*CTLogServerEntryConfig   // CT log servers
	LogServerRequester LogServerRequester                     // not set
	DB                 map[[32]byte]*common.PolicyCertificate // per hash of public key
	SerialNumber       int                                    // unique serial number per pol cert
}

// LogServerRequester is implemented by objects that can talk to CT log servers.
// TODO(juanga) implement a real one, not only a mock for the tests.
type LogServerRequester interface {
	ObtainSptFromLogServer(
		URL string,
		pc *common.PolicyCertificate,
	) (*common.SignedPolicyCertificateTimestamp, error)
	SendPolicyCertificateToLogServer(
		URL string,
		pc *common.PolicyCertificate,
	) error
}

// NewPCA: Return a new instance of PCa
func NewPCA(configPath string) (*PCA, error) {
	// read config file
	config := &PCAConfig{}
	err := ReadConfigFromFile(config, configPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | ReadConfigFromFile | %w", err)
	}

	// Load rsa key pair
	keyPair, err := util.RSAKeyFromPEMFile(config.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("NewPCA | LoadRSAKeyPairFromFile | %w", err)
	}

	// Load Root Policy Certificate.
	a, err := common.FromJSONFile(config.RootPolicyCertPath)
	if err != nil {
		return nil, err
	}
	rpc, err := util.ToType[*common.PolicyCertificate](a)
	if err != nil {
		return nil, err
	}
	// Check the private key and RPC match.
	derBytes, err := util.RSAPublicToDERBytes(&keyPair.PublicKey)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(rpc.PublicKey, derBytes) {
		return nil, fmt.Errorf("RPC and key do not match")
	}

	// Load the CT log server entries.
	logServers := make(map[[32]byte]*CTLogServerEntryConfig)
	for _, s := range config.CTLogServers {
		// Compute the hash of the public key.
		h := common.SHA256Hash32Bytes(s.PublicKeyDER)
		logServers[h] = &s
	}

	return &PCA{
		CAName:         config.CAName,
		RsaKeyPair:     keyPair,
		RootPolicyCert: rpc,
		CtLogServers:   logServers,
		DB:             make(map[[32]byte]*common.PolicyCertificate),
		SerialNumber:   0,
	}, nil
}

func (pca *PCA) NewPolicyCertificateSigningRequest(
	version int,
	subject string,
	serialNumber int,
	domain string,
	notBefore time.Time,
	notAfter time.Time,
	isIssuer bool,
	publicKey []byte,
	publicKeyAlgorithm common.PublicKeyAlgorithm,
	signatureAlgorithm common.SignatureAlgorithm,
	policyAttributes common.PolicyAttributes,
	ownerSigningFunction func(serialized []byte) []byte,
	ownerPubKeyHash []byte,
) (*common.PolicyCertificateSigningRequest, error) {

	// Check validity range falls inside PCAs.
	if notBefore.Before(pca.RootPolicyCert.NotBefore) {
		return nil, fmt.Errorf("invalid validity range: %s before PCAs %s",
			notBefore, pca.RootPolicyCert.NotBefore)
	}
	if notAfter.After(pca.RootPolicyCert.NotAfter) {
		return nil, fmt.Errorf("invalid validity range: %s after PCAs %s",
			notAfter, pca.RootPolicyCert.NotAfter)
	}

	// Create request with appropriate values.
	req := common.NewPolicyCertificateSigningRequest(
		version,
		pca.CAName,
		subject,
		serialNumber,
		domain,
		notBefore,
		notAfter,
		isIssuer,
		publicKey,
		publicKeyAlgorithm,
		signatureAlgorithm,
		time.Now(),
		policyAttributes,
		nil,
		ownerPubKeyHash,
	)
	// Serialize it.
	serializedReq, err := common.ToJSON(req)
	if err != nil {
		return nil, err
	}
	// Obtain signature.
	req.OwnerSignature = ownerSigningFunction(serializedReq)

	return req, nil
}

// SignAndLogRequest signs the policy certificate request and generates a policy certificate.
func (pca *PCA) SignAndLogRequest(
	req *common.PolicyCertificateSigningRequest,
) (*common.PolicyCertificate, error) {

	// verify the signature in the rcsr; check if the domain's pub key is correct
	skip, err := pca.canSkipCoolOffPeriod(req)
	if err != nil {
		return nil, err
	}
	if !skip {
		return nil, fmt.Errorf("for now we don't support cool off periods; all requests must " +
			"be signed by the owner")
	}

	pc, err := pca.signRequest(req)
	if err != nil {
		return nil, err
	}

	if err := pca.sendRequestToAllLogServers(pc); err != nil {
		return nil, err
	}

	if err := pca.signFinalPolicyCertificate(pc); err != nil {
		return nil, err
	}

	if err := pca.sendFinalPolCertToAllLogServers(pc); err != nil {
		return nil, err
	}

	pca.storeInDb(pc)

	return pc, nil
}

// canSkipCoolOffPeriod verifies that the owner's signature is correct, if there is an owner's
// signature in the request, and this PCA has the policy certificate used to signed said request.
// It returns true if this PCA can skip the cool off period, false otherwise.
func (pca *PCA) canSkipCoolOffPeriod(req *common.PolicyCertificateSigningRequest) (bool, error) {
	// Owner's signature?
	if len(req.OwnerSignature) == 0 {
		// No signature, cannot skip cool off period.
		return false, nil
	}
	// If there is a owner's signature, the id of the key used must be 32 bytes.
	if len(req.OwnerPubKeyHash) != 32 {
		return false, fmt.Errorf("field OwnerPubKeyHash should be 32 bytes long but is %d",
			len(req.OwnerPubKeyHash))
	}
	// Cast it to array and check the DB.
	key := (*[32]byte)(req.OwnerPubKeyHash)
	stored, ok := pca.DB[*key]
	if !ok {
		// No such certificate, cannot skip cool off period.
		return false, nil
	}

	// We found the policy certificate used to sign this request. Get the public key.
	pubKey, err := util.DERBytesToRSAPublic(stored.PublicKey)
	if err != nil {
		return false, err
	}

	// Verify the signature matches.
	err = crypto.VerifyOwnerSignature(req, pubKey)

	// Return true if no error, or false and the error.
	return err == nil, err
}

func (pca *PCA) signRequest(
	req *common.PolicyCertificateSigningRequest,
) (*common.PolicyCertificate, error) {

	// Set the issuer values from this CA.
	pca.increaseSerialNumber()
	req.Issuer = pca.RootPolicyCert.Subject()
	req.RawSerialNumber = pca.SerialNumber
	return crypto.SignRequestAsIssuer(req, pca.RsaKeyPair)
}

func (pca *PCA) sendRequestToAllLogServers(pc *common.PolicyCertificate) error {
	// TODO(juagargi) do this concurrently
	SPTs := make([]common.SignedPolicyCertificateTimestamp, 0, len(pca.CtLogServers))
	for _, logServer := range pca.CtLogServers {
		spt, err := pca.sendRequestToLogServer(pc, logServer)
		if err != nil {
			return err
		}
		SPTs = append(SPTs, *spt)
	}
	pc.SPCTs = SPTs
	return nil
}

func (pca *PCA) sendRequestToLogServer(
	pc *common.PolicyCertificate,
	logServer *CTLogServerEntryConfig,
) (*common.SignedPolicyCertificateTimestamp, error) {

	return pca.LogServerRequester.ObtainSptFromLogServer(logServer.URL, pc)
}

func (pca *PCA) signFinalPolicyCertificate(pc *common.PolicyCertificate) error {
	_, err := crypto.SignPolicyCertificateAsIssuer(pc, pca.RsaKeyPair)
	return err
}

// sendFinalPolCertToAllLogServers sends the final policy certificate with all the SPTs included,
// to all the configured CT log servers for final registration.
func (pca *PCA) sendFinalPolCertToAllLogServers(pc *common.PolicyCertificate) error {
	for _, logServer := range pca.CtLogServers {
		err := pca.LogServerRequester.SendPolicyCertificateToLogServer(logServer.URL, pc)
		if err != nil {
			return err
		}
	}
	return nil
}

func (pca *PCA) storeInDb(pc *common.PolicyCertificate) {
	key := (*[32]byte)(common.SHA256Hash(pc.PublicKey))
	pca.DB[*key] = pc
}

// TODO(yongzhe): modify this to make sure unique SN
func (pca *PCA) increaseSerialNumber() {
	pca.SerialNumber = pca.SerialNumber + 1
}
