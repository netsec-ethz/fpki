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

// SignStrucRSASHA256: generate a signature using SHA256 and RSA
func SignStrucRSASHA256(struc interface{}, privKey *rsa.PrivateKey) ([]byte, error) {
	bytes, err := JsonStrucToBytes(struc)
	if err != nil {
		return nil, fmt.Errorf("SignStrucRSASHA256 | JsonStrucToBytes | %w", err)
	}

	hashOutput := sha256.Sum256(bytes)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashOutput[:])
	if err != nil {
		return nil, fmt.Errorf("SignStrucRSASHA256 | SignPKCS1v15 | %w", err)
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

	signature, err := SignStrucRSASHA256(rcsr, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("RCSRCreateSignature | SignStrucRSASHA256 | %w", err)
	}

	rcsr.Signature = signature
	return nil
}

// RCSRGenerateRPCSignature: Generate RPC signature and fill it in the RCSR;
//    (in paper, if new rcsr has the signature from previous rpc, the cool-off can be bypassed)
func RCSRGenerateRPCSignature(rcsr *RCSR, prevPrivKeyOfPRC *rsa.PrivateKey) error {
	// clear the co-responding fields
	rcsr.Signature = []byte{}
	rcsr.PRCSignature = []byte{}

	rpcSignature, err := SignStrucRSASHA256(rcsr, prevPrivKeyOfPRC)
	if err != nil {
		return fmt.Errorf("RCSRGenerateRPCSignature | SignStrucRSASHA256 | %w", err)
	}

	rcsr.PRCSignature = rpcSignature
	return nil
}

// RCSRVerifySignature: verify the signature using the public key in hash
func RCSRVerifySignature(rcsr *RCSR) error {
	// Signature will be empty
	rcsrCopy := &RCSR{
		Subject:            rcsr.Subject,
		Version:            rcsr.Version,
		TimeStamp:          rcsr.TimeStamp,
		PublicKeyAlgorithm: rcsr.PublicKeyAlgorithm,
		PublicKey:          rcsr.PublicKey,
		SignatureAlgorithm: rcsr.SignatureAlgorithm,
		PRCSignature:       rcsr.PRCSignature,
		Signature:          []byte{},
	}

	serialisedStruc, err := JsonStrucToBytes(rcsrCopy)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | JsonStrucToBytes | %w", err)
	}

	// get the pub key
	pubKey, err := PemBytesToRsaPublicKey(rcsr.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serialisedStruc)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.Signature)
	if err != nil {
		return fmt.Errorf("RCSRVerifySignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// RCSRVerifyRPCSignature: verify the RCSR using RPC; verify the RPC signature
func RCSRVerifyRPCSignature(rcsr *RCSR, rpc *RPC) error {
	rcsrCopy := &RCSR{
		Subject:            rcsr.Subject,
		Version:            rcsr.Version,
		TimeStamp:          rcsr.TimeStamp,
		PublicKeyAlgorithm: rcsr.PublicKeyAlgorithm,
		PublicKey:          rcsr.PublicKey,
		SignatureAlgorithm: rcsr.SignatureAlgorithm,
		PRCSignature:       []byte{},
		Signature:          []byte{},
	}

	serialisedStruc, err := JsonStrucToBytes(rcsrCopy)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | JsonStrucToBytes | %w", err)
	}

	pubKey, err := PemBytesToRsaPublicKey(rpc.PublicKey)
	if err != nil {
		return fmt.Errorf("RCSRVerifyRPCSignature | PemBytesToRsaPublicKey | %w", err)
	}

	hashOutput := sha256.Sum256(serialisedStruc)
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

	signature, err := SignStrucRSASHA256(rpc, caPrivKey)
	if err != nil {
		return nil, fmt.Errorf("RCSRGenerateRPC | SignStrucRSASHA256 | %w", err)
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

	rpcCopy := &RPC{
		SerialNumber:       rpc.SerialNumber,
		Subject:            rpc.Subject,
		Version:            rpc.Version,
		PublicKeyAlgorithm: rpc.PublicKeyAlgorithm,
		PublicKey:          rpc.PublicKey,
		NotBefore:          rpc.NotBefore,
		NotAfter:           rpc.NotAfter,
		CAName:             rpc.CAName,
		SignatureAlgorithm: rpc.SignatureAlgorithm,
		TimeStamp:          rpc.TimeStamp,
		PRCSignature:       rpc.PRCSignature,
		CASignature:        []byte{},
		SPTs:               []SPT{},
	}

	bytes, err := JsonStrucToBytes(rpcCopy)
	if err != nil {
		return fmt.Errorf("RPCVerifyCASignature | JsonStrucToBytes | %w", err)
	}

	hashOutput := sha256.Sum256(bytes)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rpc.CASignature)
	if err != nil {
		return fmt.Errorf("RPCVerifyCASignature | VerifyPKCS1v15 | %w", err)
	}
	return nil
}

// ----------------------------------------------------------------------------------
//                               functions on PC
// ----------------------------------------------------------------------------------
// DomainOwnerSignPC: Used by domain owner to sign the PC
func DomainOwnerSignPC(domainOwnerPrivKey *rsa.PrivateKey, pc *PC) error {
	pc.SPTs = []SPT{}
	pc.RootCertSignature = []byte{}
	pc.CASignature = []byte{}
	pc.SerialNumber = 0
	pc.CAName = ""
	pc.TimeStamp = time.Time{}

	signature, err := SignStrucRSASHA256(pc, domainOwnerPrivKey)
	if err != nil {
		return fmt.Errorf("DomainOwnerSignPC | SignStrucRSASHA256 | %w", err)
	}

	pc.RootCertSignature = signature
	return nil
}

//CAVerifyPCAndSign: verify the signature and sign the signature
func CAVerifyPCAndSign(domainOwnerCert *x509.Certificate, pc PC, caPrivKey *rsa.PrivateKey, caName string, serialNum int) (PC, error) {
	if len(pc.RootCertSignature) == 0 {
		return PC{}, fmt.Errorf("CAVerifyPCAndSign | no valid signature")
	}

	pcCopy := PC{
		Policies: pc.Policies,
		Subject:  pc.Subject,
	}

	serialisedStruc, err := JsonStrucToBytes(&pcCopy)
	if err != nil {
		return PC{}, fmt.Errorf("CAVerifyPCAndSign | JsonStrucToBytes | %w", err)
	}

	hashOutput := sha256.Sum256(serialisedStruc)
	err = rsa.VerifyPKCS1v15(domainOwnerCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashOutput[:], pc.RootCertSignature)
	if err != nil {
		return PC{}, fmt.Errorf("CAVerifyPCAndSign | VerifyPKCS1v15 | %w", err)
	}

	pcCopy.RootCertSignature = pc.RootCertSignature
	pcCopy.TimeStamp = time.Now()
	pcCopy.CAName = caName
	pcCopy.SerialNumber = serialNum

	caSignature, err := SignStrucRSASHA256(&pcCopy, caPrivKey)
	if err != nil {
		return PC{}, fmt.Errorf("CAVerifyPCAndSign | SignStrucRSASHA256 | %w", err)
	}

	pcCopy.CASignature = caSignature
	return pcCopy, nil
}

// VerifyCASigInPC: verify CA's signature
func VerifyCASigInPC(caCert *x509.Certificate, pc PC) error {
	if len(pc.CASignature) == 0 {
		return fmt.Errorf("VerifyCASigInPC | no valid CA signature")
	}

	pcCopy := PC{
		Policies:          pc.Policies,
		Subject:           pc.Subject,
		RootCertSignature: pc.RootCertSignature,
		TimeStamp:         pc.TimeStamp,
		CAName:            pc.CAName,
		SerialNumber:      pc.SerialNumber,
	}

	serialisedStruc, err := JsonStrucToBytes(&pcCopy)
	if err != nil {
		return fmt.Errorf("VerifyCASigInPC | JsonStrucToBytes | %w", err)
	}

	hashOutput := sha256.Sum256(serialisedStruc)
	err = rsa.VerifyPKCS1v15(caCert.PublicKey.(*rsa.PublicKey), crypto.SHA256, hashOutput[:], pc.CASignature)
	if err != nil {
		return fmt.Errorf("VerifyCASigInPC | VerifyPKCS1v15 | %w", err)
	}
	return nil
}
