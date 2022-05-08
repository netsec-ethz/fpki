package mapserver

type DomainEntry struct {
	domainName   string
	certificates [][]byte
}

type UpdateInput struct {
	key   []byte
	value []byte
}

type Proof struct {
	domain string
	poi    PoI
}

type PoI struct {
	proofType  ProofType
	proof      [][]byte
	root       []byte
	proofKey   []byte
	proofValue []byte
}

type ProofType int

const (
	PoA ProofType = iota
	PoP ProofType = iota
)
