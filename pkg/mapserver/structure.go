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
	proof [][]byte
	root  []byte
}
