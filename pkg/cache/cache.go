package cache

import "github.com/netsec-ethz/fpki/pkg/common"

type Cache interface {
	Contains(*common.SHA256Output) bool
	AddIDs(...*common.SHA256Output)
}
