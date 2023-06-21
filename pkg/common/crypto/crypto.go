package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
)

func SignBytes(b []byte, key *rsa.PrivateKey) ([]byte, error) {
	hashOutput := sha256.Sum256(b)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashOutput[:])
	if err != nil {
		return nil, fmt.Errorf("SignBytes | SignPKCS1v15 | %w", err)
	}
	return signature, nil
}

// ----------------------------------------------------------------------------------
//                               functions on RCSR
// ----------------------------------------------------------------------------------

// RCSRCreateSignature: Generate a signature, and fill the signature in the RCSR
func RCSRCreateSignature(domainOwnerPrivKey *rsa.PrivateKey, rcsr *common.RCSR) error {
	// clear signature; normally should be empty
	rcsr.Signature = []byte{}

	signature, err := signStructRSASHA256(rcsr, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("RCSRCreateSignature | SignStructRSASHA256 | %w", err)
	}

	rcsr.Signature = signature
	return nil
}

// RCSRGenerateRPCSignature: Generate RPC signature and fill it in the RCSR;
//
//	(in paper, if new rcsr has the signature from previous rpc, the cool-off can be bypassed)
func RCSRGenerateRPCSignature(rcsr *common.RCSR, prevPrivKeyOfPRC *rsa.PrivateKey) error {
	// clear the co-responding fields
	rcsr.Signature = []byte{}
	rcsr.PRCSignature = []byte{}

	rpcSignature, err := signStructRSASHA256(rcsr, prevPrivKeyOfPRC)
	if err != nil {
		return fmt.Errorf("RCSRGenerateRPCSignature | SignStructRSASHA256 | %w", err)
	}

	rcsr.PRCSignature = rpcSignature
	return nil
}

// RCSRVerifySignature: verify the signature using the public key in hash
func RCSRVerifySignature(rcsr *common.RCSR) error {
	// Serialize without signature:
	sig := rcsr.Signature
	rcsr.Signature = nil
	serializedStruct, err := common.ToJSON(rcsr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	rcsr.Signature = sig

	// Get the pub key:
	pubKey, err := util.PEMToRSAPublic(rcsr.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.Signature)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// RCSRVerifyRPCSignature: verify the RCSR using RPC; verify the RPC signature
func RCSRVerifyRPCSignature(rcsr *common.RCSR, rpc *common.PolicyCertificate) error {
	// Serialize without signature:
	sig := rcsr.Signature
	rcsr.Signature = nil
	serializedStruct, err := common.ToJSON(rcsr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	rcsr.Signature = sig

	pubKey, err := util.PEMToRSAPublic(rpc.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.PRCSignature)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// RCSRGenerateRPC: called by PCA. Sign the RCSR and generate RPC; SPT field is (should be) empty
func RCSRGenerateRPC(rcsr *common.RCSR, notBefore time.Time, serialNumber int,
	caPrivKey *rsa.PrivateKey, caName string) (*common.PolicyCertificate, error) {

	rpc := common.NewPolicyCertificate(
		rcsr.RawSubject,
		nil, // policy attributes
		serialNumber,
		rcsr.Version,
		rcsr.PublicKeyAlgorithm,
		rcsr.PublicKey,
		notBefore,
		time.Now().AddDate(0, 0, 90),
		caName,
		common.SHA256,
		time.Now(),
		rcsr.PRCSignature,
		[]byte{},
		nil,
	)

	signature, err := signStructRSASHA256(rpc, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("RCSRGenerateRPC | SignStructRSASHA256 | %w", err)
	}

	rpc.CASignature = signature
	return rpc, nil
}

// ----------------------------------------------------------------------------------
//                               functions on RPC
// ----------------------------------------------------------------------------------

// RPCVerifyCASignature: used by domain owner, check whether CA signature is correct
func RPCVerifyCASignature(caCert *ctx509.Certificate, rpc *common.PolicyCertificate) error {
	pubKey := caCert.PublicKey.(*rsa.PublicKey)

	// Serialize without CA signature or SPTs:
	caSig, SPTs := rpc.CASignature, rpc.SPTs
	rpc.CASignature, rpc.SPTs = nil, nil
	bytes, err := common.ToJSON(rpc)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	rpc.CASignature, rpc.SPTs = caSig, SPTs

	hashOutput := sha256.Sum256(bytes)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rpc.CASignature)
	if err != nil {
		return fmt.Errorf("RPCVerifyCASignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------------
//                               functions on SP
// ----------------------------------------------------------------------------------

// DomainOwnerSignSP: Used by domain owner to sign the PC
func DomainOwnerSignPSR(domainOwnerPrivKey *rsa.PrivateKey, psr *common.PSR) error {
	signature, err := signStructRSASHA256(psr, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("DomainOwnerSignPC | SignStructRSASHA256 | %w", err)
	}

	psr.RootCertSignature = signature
	return nil
}

func VerifyPSRUsingRPC(psr *common.PSR, rpc *common.PolicyCertificate) error {
	// Serialize without signature:
	sig := psr.RootCertSignature
	psr.RootCertSignature = nil
	serializedStruct, err := common.ToJSON(psr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	psr.RootCertSignature = sig

	pubKey, err := util.PEMToRSAPublic(rpc.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], psr.RootCertSignature)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | VerifyPKCS1v15 | %w", err)
	}

	return nil
}

// CAVerifySPAndSign: verify the signature and sign the signature
func CASignSP(psr *common.PSR, caPrivKey *rsa.PrivateKey, caName string, serialNum int) (
	*common.SP, error) {

	sp := common.NewSP(
		psr.RawSubject,
		psr.Policy,
		time.Now(),
		caName,
		serialNum,
		nil,
		psr.RootCertSignature,
		nil,
	)

	caSignature, err := signStructRSASHA256(sp, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("CASignSP | SignStructRSASHA256 | %w", err)
	}

	sp.CASignature = caSignature
	return sp, nil
}

// VerifyCASigInSP: verify CA's signature
func VerifyCASigInSP(caCert *ctx509.Certificate, sp *common.SP) error {
	if len(sp.CASignature) == 0 {
		return fmt.Errorf("VerifyCASigInPC | no valid CA signature")
	}

	// Serialize without CA signature or SPTs:
	caSig, SPTs := sp.CASignature, sp.SPTs
	sp.CASignature, sp.SPTs = nil, nil
	serializedStruct, err := common.ToJSON(sp)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | ToJSON | %w", err)
	}
	sp.CASignature, sp.SPTs = caSig, SPTs

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(caCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashOutput[:], sp.CASignature)
	if err != nil {
		return fmt.Errorf("VerifyCASigInPC | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// signStructRSASHA256: generate a signature using SHA256 and RSA
func signStructRSASHA256(s any, key *rsa.PrivateKey) ([]byte, error) {
	b, err := common.ToJSON(s)
	if err != nil {
		return nil, fmt.Errorf("SignStructRSASHA256 | ToJSON | %w", err)
	}
	return SignBytes(b, key)
}
