package testdb

import (
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func BuildTestPolicyHierarchy(t require.TestingT, domainName string) []common.PolicyObject {
	// Create one RPC and one SP for that name.
	rpc := &common.RPC{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: domainName,
		},
		SerialNumber: 1,
		Version:      1,
		PublicKey:    util.RandomBytesForTest(t, 32),
		CAName:       "c0.com",
		CASignature:  util.RandomBytesForTest(t, 100),
	}
	sp := &common.SP{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: domainName,
		},
		CAName:            "c0.com",
		CASignature:       util.RandomBytesForTest(t, 100),
		RootCertSignature: util.RandomBytesForTest(t, 100),
	}
	return []common.PolicyObject{rpc, sp}
}
