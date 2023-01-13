package common

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
)

// SignatureAlgorithm: Enum of supported signature algorithm; Currently only SHA256
// currently only SHA256 and RSA is supported
type SignatureAlgorithm int

const (
	SHA256 SignatureAlgorithm = iota
)

// PublicKeyAlgorithm: Enum of supported public key algorithm; Currently only RSA
type PublicKeyAlgorithm int

const (
	RSA PublicKeyAlgorithm = iota
)

// SignStructRSASHA256: generate a signature using SHA256 and RSA
func SignStructRSASHA256(s interface{}, privKey *rsa.PrivateKey) ([]byte, error) {
	bytes, err := JsonStructToBytes(s)
	if err != nil {
		return nil, fmt.Errorf("SignStructRSASHA256 | JsonStructToBytes | %w", err)
	}

	hashOutput := sha256.Sum256(bytes)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashOutput[:])
	if err != nil {
		return nil, fmt.Errorf("SignStructRSASHA256 | SignPKCS1v15 | %w", err)
	}
	return signature, nil
}

// ----------------------------------------------------------------------------------
//                               functions on RCSR
// ----------------------------------------------------------------------------------

// RCSRCreateSignature: Generate a signature, and fill the signature in the RCSR
func RCSRCreateSignature(domainOwnerPrivKey *rsa.PrivateKey, rcsr *RCSR) error {
	// clear signature; normally should be empty
	rcsr.Signature = []byte{}

	signature, err := SignStructRSASHA256(rcsr, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("RCSRCreateSignature | SignStructRSASHA256 | %w", err)
	}

	rcsr.Signature = signature
	return nil
}

// RCSRGenerateRPCSignature: Generate RPC signature and fill it in the RCSR;
//
//	(in paper, if new rcsr has the signature from previous rpc, the cool-off can be bypassed)
func RCSRGenerateRPCSignature(rcsr *RCSR, prevPrivKeyOfPRC *rsa.PrivateKey) error {
	// clear the co-responding fields
	rcsr.Signature = []byte{}
	rcsr.PRCSignature = []byte{}

	rpcSignature, err := SignStructRSASHA256(rcsr, prevPrivKeyOfPRC)
	if err != nil {
		return fmt.Errorf("RCSRGenerateRPCSignature | SignStructRSASHA256 | %w", err)
	}

	rcsr.PRCSignature = rpcSignature
	return nil
}

// RCSRVerifySignature: verify the signature using the public key in hash
func RCSRVerifySignature(rcsr *RCSR) error {
	// Serialize without signature:
	sig := rcsr.Signature
	rcsr.Signature = nil
	serializedStruct, err := JsonStructToBytes(rcsr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStructToBytes | %w", err)
	}
	rcsr.Signature = sig

	// Get the pub key:
	pubKey, err := PemBytesToRsaPublicKey(rcsr.PublicKey)
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
func RCSRVerifyRPCSignature(rcsr *RCSR, rpc *RPC) error {
	// Serialize without signature:
	sig := rcsr.Signature
	rcsr.Signature = nil
	serializedStruct, err := JsonStructToBytes(rcsr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStructToBytes | %w", err)
	}
	rcsr.Signature = sig

	pubKey, err := PemBytesToRsaPublicKey(rpc.PublicKey)
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
func RCSRGenerateRPC(rcsr *RCSR, notBefore time.Time, serialNumber int, caPrivKey *rsa.PrivateKey, caName string) (*RPC, error) {
	rpc := &RPC{
		Subject:            rcsr.Subject,
		Version:            rcsr.Version,
		PublicKeyAlgorithm: rcsr.PublicKeyAlgorithm,
		PublicKey:          rcsr.PublicKey,
		CAName:             caName,
		SignatureAlgorithm: SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       rcsr.PRCSignature,
		NotBefore:          notBefore,
		NotAfter:           time.Now().AddDate(0, 0, 90),
		SerialNumber:       serialNumber,
		CASignature:        []byte{},
		SPTs:               []SPT{},
	}

	signature, err := SignStructRSASHA256(rpc, caPrivKey)
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
func RPCVerifyCASignature(caCert *x509.Certificate, rpc *RPC) error {
	pubKey := caCert.PublicKey.(*rsa.PublicKey)

	// Serialize without CA signature or SPTs:
	caSig, SPTs := rpc.CASignature, rpc.SPTs
	rpc.CASignature, rpc.SPTs = nil, nil
	bytes, err := JsonStructToBytes(rpc)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStructToBytes | %w", err)
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
func DomainOwnerSignPSR(domainOwnerPrivKey *rsa.PrivateKey, psr *PSR) error {
	signature, err := SignStructRSASHA256(psr, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("DomainOwnerSignPC | SignStructRSASHA256 | %w", err)
	}

	psr.RootCertSignature = signature
	return nil
}

func VerifyPSRUsingRPC(psr *PSR, rpc *RPC) error {
	// Serialize without signature:
	sig := psr.RootCertSignature
	psr.RootCertSignature = nil
	serializedStruct, err := JsonStructToBytes(psr)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStructToBytes | %w", err)
	}
	psr.RootCertSignature = sig

	pubKey, err := PemBytesToRsaPublicKey(rpc.PublicKey)
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
func CASignSP(psr *PSR, caPrivKey *rsa.PrivateKey, caName string, serialNum int) (*SP, error) {
	sp := &SP{
		Policies:          psr.Policies,
		Subject:           psr.DomainName,
		RootCertSignature: psr.RootCertSignature,
		TimeStamp:         time.Now(),
		CAName:            caName,
		SerialNumber:      serialNum,
	}

	caSignature, err := SignStructRSASHA256(sp, caPrivKey)
	if err != nil {
		return &SP{}, fmt.Errorf("CASignSP | SignStructRSASHA256 | %w", err)
	}

	sp.CASignature = caSignature
	return sp, nil
}

// VerifyCASigInSP: verify CA's signature
func VerifyCASigInSP(caCert *x509.Certificate, sp *SP) error {
	if len(sp.CASignature) == 0 {
		return fmt.Errorf("VerifyCASigInPC | no valid CA signature")
	}

	// Serialize without CA signature or SPTs:
	caSig, SPTs := sp.CASignature, sp.SPTs
	sp.CASignature, sp.SPTs = nil, nil
	serializedStruct, err := JsonStructToBytes(sp)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStructToBytes | %w", err)
	}
	sp.CASignature, sp.SPTs = caSig, SPTs

	hashOutput := sha256.Sum256(serializedStruct)
	err = rsa.VerifyPKCS1v15(caCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashOutput[:], sp.CASignature)
	if err != nil {
		return fmt.Errorf("VerifyCASigInPC | VerifyPKCS1v15 | %w", err)
	}
	return nil
}
