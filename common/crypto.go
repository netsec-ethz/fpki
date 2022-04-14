package common

import (
    "bytes"
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/gob"
    "encoding/pem"
    "errors"
    "fmt"
    "io/ioutil"
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

// ----------------------------------------------------------------------------------
//                                    common part
// ----------------------------------------------------------------------------------

func SignStruc_RSA_SHA256(struc interface{}, privKey *rsa.PrivateKey) ([]byte, error) {
    //hash the RCSR using SHA256
    var bytesBuffer bytes.Buffer
    encoder := gob.NewEncoder(&bytesBuffer)
    err := encoder.Encode(struc)
    if err != nil {
        return []byte{}, fmt.Errorf("SignStruc_RSA_SHA256 | Encode | %s", err.Error())
    }
    hashOutput := sha256.Sum256(bytesBuffer.Bytes())

    signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashOutput[:])
    if err != nil {
        return []byte{}, fmt.Errorf("SignStruc_RSA_SHA256 | SignPKCS1v15 | %s", err.Error())
    }

    return signature, nil
}

// ----------------------------------------------------------------------------------
//                     Key or certificate related functions
// ----------------------------------------------------------------------------------

func RsaPublicKeyToPemBytes(pubkey *rsa.PublicKey) ([]byte, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
        return []byte{}, fmt.Errorf("RsaPublicKeyToPemBytes | MarshalPKIXPublicKey | %s", err.Error())
    }
    pubkey_pem := pem.EncodeToMemory(
        &pem.Block{
            Type:  "RSA PUBLIC KEY",
            Bytes: pubkey_bytes,
        },
    )

    return pubkey_pem, nil
}

func PemBytesToRsaPublicKey(pubkey []byte) (*rsa.PublicKey, error) {
    block, _ := pem.Decode(pubkey)
    if block == nil {
        return nil, fmt.Errorf("PemBytesToRsaPublicKey | Decode")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("PemBytesToRsaPublicKey | ParsePKIXPublicKey | %s", err.Error())
    }

    switch pub := pub.(type) {
    case *rsa.PublicKey:
        return pub, nil
    default:
        break
    }
    return nil, errors.New("Key type is not RSA")
}

func X509CertFromFile(fileName string) (*x509.Certificate, error) {
    content, err := ioutil.ReadFile(fileName)

    if err != nil {
        return nil, fmt.Errorf("X509CertFromFile | failed to read %s: %s", fileName, err)
    }

    var block *pem.Block
    block, _ = pem.Decode(content)

    if block == nil {
        return nil, fmt.Errorf("X509CertFromFile | no pem block in %s", fileName)
    }

    if block.Type != "CERTIFICATE" {
        return nil, fmt.Errorf("X509CertFromFile | %s contains data other than certificate", fileName)
    }

    cert, err := x509.ParseCertificate(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("X509CertFromFile | ParseCertificate | %s", err.Error())
    }

    return cert, nil
}

func X509CertToFile() {

}

func LoadRSAKeyPairFromFile(keyPath string) (*rsa.PrivateKey, error) {
    bytes, err := ioutil.ReadFile(keyPath)
    if err != nil {
        return nil, fmt.Errorf("LoadPrivPubKeyFromFile | read file | %s", err.Error())
    }

    block, _ := pem.Decode(bytes)

    keyPair, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("LoadPrivPubKeyFromFile | ParsePKCS1PrivateKey |%s", err.Error())
    }
    return keyPair, nil
}

func RSAKeyPairToFile() {

}

// ----------------------------------------------------------------------------------
//                               functions on RCSR
// ----------------------------------------------------------------------------------

//called by domain owner
func SignRCSR(domainOwnerPrivKey *rsa.PrivateKey, rcsr *RCSR) error {
    // clear signature; normally should be
    rcsr.Signature = []byte{}

    signature, err := SignStruc_RSA_SHA256(rcsr, domainOwnerPrivKey)
    if err != nil {
        return fmt.Errorf("SignRCSR | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rcsr.Signature = signature
    return nil
}

// verify the signature using the public key in hash
func VerifyRCSR(rcsr *RCSR) error {
    // deep copy; Signature will be empty
    rcsrCopy := RCSR{
        Subject:            rcsr.Subject,
        Version:            rcsr.Version,
        TimeStamp:          rcsr.TimeStamp,
        PublicKeyAlgorithm: rcsr.PublicKeyAlgorithm,
        PublicKey:          rcsr.PublicKey,
        SignatureAlgorithm: rcsr.SignatureAlgorithm,
        PRCSignature:       rcsr.PRCSignature,
        Signature:          []byte{},
    }

    serialisedStruc, err := SerialiseStruc(rcsrCopy)
    if err != nil {
        return fmt.Errorf("VerifyRCSR | SerialiseStruc | %s", err.Error())
    }

    pubKey, err := PemBytesToRsaPublicKey(rcsr.PublicKey)
    if err != nil {
        return fmt.Errorf("VerifyRCSR | PemBytesToRsaPublicKey | %s", err.Error())
    }

    hashOutput := sha256.Sum256(serialisedStruc)

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rcsr.Signature)
    return err
}

// verify the RCSR using RPC
func VerifyRCSRByRPC(rcsr *RCSR, rpc *RPC) error {
    // deep copy
    rcsrCopy := RCSR{
        Subject:            rcsr.Subject,
        Version:            rcsr.Version,
        TimeStamp:          rcsr.TimeStamp,
        PublicKeyAlgorithm: rcsr.PublicKeyAlgorithm,
        PublicKey:          rcsr.PublicKey,
        SignatureAlgorithm: rcsr.SignatureAlgorithm,
        PRCSignature:       []byte{},
        Signature:          []byte{},
    }

    serialisedStruc, err := SerialiseStruc(rcsrCopy)
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

func GeneratePRCSignatureForRCSR(rcsr *RCSR, prevPrivKeyOfPRC *rsa.PrivateKey) error {
    rcsr.Signature = []byte{}
    rcsr.PRCSignature = []byte{}

    rpcSignature, err := SignStruc_RSA_SHA256(rcsr, prevPrivKeyOfPRC)
    if err != nil {
        return fmt.Errorf("SignRCSR | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rcsr.PRCSignature = rpcSignature
    return nil
}

// ----------------------------------------------------------------------------------
//                               functions on RPC
// ----------------------------------------------------------------------------------

// called by PCA. Sign the RCSR and generate RPC; SPT field is empty
func RCSRToRPC(rcsr *RCSR, notBefore time.Time, serialNumber int, caPrivKey *rsa.PrivateKey, caName string) (*RPC, error) {
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
        SPTs:               []SPT{},
    }

    signature, err := SignStruc_RSA_SHA256(rpc, caPrivKey)
    if err != nil {
        return nil, fmt.Errorf("RCSRToRPC | SignStruc_RSA_SHA256 | %s", err.Error())
    }

    rpc.CASignature = signature

    return rpc, nil
}

// used by domain owner, check whether CA signature is correct
func VerifyRPC(caCert *x509.Certificate, rpc *RPC) error {
    pubKey := caCert.PublicKey.(*rsa.PublicKey)

    // deep copy
    rpcCopy := RPC{
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

    var bytesBuffer bytes.Buffer
    encoder := gob.NewEncoder(&bytesBuffer)
    err := encoder.Encode(rpcCopy)
    if err != nil {
        return fmt.Errorf("VerifyRPC | Encode | %s", err.Error())
    }

    hashOutput := sha256.Sum256(bytesBuffer.Bytes())

    err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashOutput[:], rpc.CASignature)

    // if every thing is correct, the err will be nil
    return err

}
