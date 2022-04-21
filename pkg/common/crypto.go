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

// currently only SHA256 and RSA is supported
type SignatureAlgorithm int

const (
    SHA256 SignatureAlgorithm = iota
)

type PublicKeyAlgorithm int

const (
    RSA PublicKeyAlgorithm = iota
)

// Common: All serialisations use the json lib.

// ----------------------------------------------------------------------------------
//                                    common part
// ----------------------------------------------------------------------------------

// generate a signature using SHA256 and RSA
func SignStruc_RSA_SHA256(struc interface{}, privKey *rsa.PrivateKey) ([]byte, error) {
    bytes, err := Json_StrucToBytes(struc)
    if err != nil {
        return []byte{}, fmt.Errorf("SignStruc_RSA_SHA256 | Encode | %s", err.Error())
    }

    hashOutput := sha256.Sum256(bytes)

    signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashOutput[:])
    if err != nil {
        return []byte{}, fmt.Errorf("SignStruc_RSA_SHA256 | SignPKCS1v15 | %s", err.Error())
    }

    return signature, nil
}

// ----------------------------------------------------------------------------------
//                               functions on RCSR
// ----------------------------------------------------------------------------------

// Generate a signature, and fill the signature in the RCSR
func RCSR_CreateSignature(domainOwnerPrivKey *rsa.PrivateKey, rcsr *RCSR) error {
    // clear signature; normally should be
    rcsr.Signature = []byte{}

    signature, err := SignStruc_RSA_SHA256(rcsr, domainOwnerPrivKey)
    if err != nil {
        return fmt.Errorf("SignRCSR | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rcsr.Signature = signature
    return nil
}

// Generate RPC signature and fill it in the RCSR; (in paper, if new rcsr has the signature from previous rpc, the cool-off can be bypassed)
func RCSR_GenerateRPCSignature(rcsr *RCSR, prevPrivKeyOfPRC *rsa.PrivateKey) error {
    // clear the co-responding fields
    rcsr.Signature = []byte{}
    rcsr.PRCSignature = []byte{}

    rpcSignature, err := SignStruc_RSA_SHA256(rcsr, prevPrivKeyOfPRC)
    if err != nil {
        return fmt.Errorf("SignRCSR | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rcsr.PRCSignature = rpcSignature
    return nil
}

// verify the signature using the public key in hash
func RCSR_VerifySignature(rcsr *RCSR) error {
    // deep copy; Signature will be empty
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

    serialisedStruc, err := Json_StrucToBytes(rcsrCopy)
    if err != nil {
        return fmt.Errorf("VerifyRCSR | SerialiseStruc | %s", err.Error())
    }

    // get the pub key
    pubKey, err := PemBytesToRsaPublicKey(rcsr.PublicKey)
    if err != nil {
        return fmt.Errorf("VerifyRCSR | PemBytesToRsaPublicKey | %s", err.Error())
    }

    hashOutput := sha256.Sum256(serialisedStruc)

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.Signature)
    return err
}

// verify the RCSR using RPC; verify the RPC signature
func RCSR_VerifyRPCSIgnature(rcsr *RCSR, rpc *RPC) error {
    // deep copy
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

    serialisedStruc, err := Json_StrucToBytes(rcsrCopy)
    if err != nil {
        return fmt.Errorf("VerifyRCSRByRPC | SerialiseStruc | %s", err.Error())
    }

    pubKey, err := PemBytesToRsaPublicKey(rpc.PublicKey)
    if err != nil {
        return fmt.Errorf("VerifyRCSRByRPC | PemBytesToRsaPublicKey | %s", err.Error())
    }

    hashOutput := sha256.Sum256(serialisedStruc)

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.PRCSignature)

    // if every thing is correct, the err will be nil
    return err
}

// called by PCA. Sign the RCSR and generate RPC; SPT field is (should be) empty
func RCSR_GenerateRPC(rcsr *RCSR, notBefore time.Time, serialNumber int, caPrivKey *rsa.PrivateKey, caName string) (*RPC, error) {
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

    signature, err := SignStruc_RSA_SHA256(rpc, caPrivKey)

    if err != nil {
        return nil, fmt.Errorf("RCSRToRPC | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rpc.CASignature = signature

    return rpc, nil
}

// ----------------------------------------------------------------------------------
//                               functions on RPC
// ----------------------------------------------------------------------------------

// used by domain owner, check whether CA signature is correct
func RPC_VerifyCASignature(caCert *x509.Certificate, rpc *RPC) error {
    pubKey := caCert.PublicKey.(*rsa.PublicKey)

    // deep copy
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

    bytes, err := Json_StrucToBytes(rpcCopy)
    if err != nil {
        return fmt.Errorf("VerifyRPC | Encode | %s", err.Error())
    }

    hashOutput := sha256.Sum256(bytes)

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rpc.CASignature)

    // if every thing is correct, the err will be nil
    return err
}
