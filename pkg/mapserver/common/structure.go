package common

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/common"
)

type ProofType int

const (
	PoA ProofType = iota
	PoP ProofType = iota
)

type DomainEntry struct {
	DomainName string
	CAEntry    []CAEntry
}

// TODO(yongzhe): add PC
type CAEntry struct {
	CAName           string
	CurrentRPC       common.RPC
	FutureRPC        common.RPC
	Revocation       [][]byte
	FutureRevocation [][]byte
	DomainCerts      [][]byte
}

func SerialiseDomainEnrty(domainEntry *DomainEntry) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(*domainEntry); err != nil {
		return nil, fmt.Errorf("SerialiseDomainEnrty | Encode | %w", err)
	}
	return buf.Bytes(), nil
}

func DesrialiseDomainEnrty(input []byte) (*DomainEntry, error) {
	buf := bytes.NewBuffer(input)
	dec := gob.NewDecoder(buf)

	result := &DomainEntry{}
	if err := dec.Decode(result); err != nil {
		return nil, fmt.Errorf("DesrialiseDomainEnrty | Decode | %w", err)
	}
	return result, nil
}

type UpdateInput struct {
	Key   []byte
	Value []byte
}

type Proof struct {
	Domain           string
	DomainEntryBytes []byte
	PoI              PoI
}

type PoI struct {
	ProofType  ProofType
	Proof      [][]byte
	Root       []byte
	ProofKey   []byte
	ProofValue []byte
}

func FlattenBytesSlice(input [][]byte) []byte {
	result := []byte{}
	for _, v := range input {
		result = append(result, v...)
	}
	return result
}
