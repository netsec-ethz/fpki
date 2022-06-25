package responder

import (
	"context"
	"fmt"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
)

func (mapResponder *MapResponder) GetDomainProofsTest(ctx context.Context, domainNames []string) (map[string][]*mapCommon.MapServerResponse, int, error) {
	start := time.Now()
	domainResultMap, domainProofMap, err := getMapping(domainNames)
	if err != nil {
		return nil, 0, fmt.Errorf("GetDomainProofs | getMapping | %w", err)
	}
	end := time.Now()

	start1 := time.Now()
	domainToFetch, err := mapResponder.getProofFromSMT(ctx, domainProofMap)
	if err != nil {
		return nil, 0, fmt.Errorf("GetDomainProofs | getProofFromSMT | %w", err)
	}
	end1 := time.Now()
	start2 := time.Now()
	result, err := mapResponder.conn.RetrieveDomainEntries(ctx, domainToFetch)
	if err != nil {
		return nil, 0, fmt.Errorf("GetDomainProofs | RetrieveKeyValuePairMultiThread | %w", err)
	}
	end2 := time.Now()
	for _, keyValuePair := range result {
		domainProofMap[keyValuePair.Key].DomainEntryBytes = keyValuePair.Value
	}

	fmt.Println(len(domainResultMap), end.Sub(start), " ", end1.Sub(start1), " ", end2.Sub(start2))
	return domainResultMap, countReadSize(result), nil
}

func countReadSize(input []*db.KeyValuePair) int {
	size := 0
	for _, pair := range input {
		size = size + len(pair.Value)
	}
	return size
}
