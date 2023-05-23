package common

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
