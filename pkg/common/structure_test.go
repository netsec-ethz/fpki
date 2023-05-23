package common_test

import (
	"math/rand"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
)

var update = tests.UpdateGoldenFiles()

func TestGenerateGoldenFiles(t *testing.T) {
	// Update the JSON files in tests/testdata
	if *update {
		obj := []any{randomSP(t), randomSP(t)}
		err := common.ToJSONFile(obj, "../../tests/testdata/2-SPs.json")
		require.NoError(t, err)
	}
}

// TestEqual: Equal funcs for every structure
func TestEqual(t *testing.T) {
	rcsr := &common.RCSR{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "bandqhvdbdlwnd",
		},
		Version:            6789,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          random.RandomBytesForTest(t, 32),
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       random.RandomBytesForTest(t, 32),
		Signature:          random.RandomBytesForTest(t, 32),
	}

	require.True(t, rcsr.Equal(rcsr), "RCSR Equal() error")

	spt1 := common.SPT{
		Version: 12313,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "hihihihihhi",
		},
		CAName:          "I'm honest CA, nice to meet you",
		LogID:           1231323,
		CertType:        0x11,
		AddedTS:         time.Now(),
		STH:             random.RandomBytesForTest(t, 32),
		PoI:             random.RandomBytesForTest(t, 32),
		STHSerialNumber: 131678,
		Signature:       random.RandomBytesForTest(t, 32),
	}

	spt2 := common.SPT{
		Version: 12368713,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "hohohoho",
		},
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             random.RandomBytesForTest(t, 32),
		PoI:             random.RandomBytesForTest(t, 32),
		STHSerialNumber: 114378,
		Signature:       random.RandomBytesForTest(t, 32),
	}

	require.True(t, spt1.Equal(spt1) && spt2.Equal(spt2) && !spt1.Equal(spt2) && !spt2.Equal(spt1), "SPT Equal() error")

	sprt := &common.SPRT{
		SPT: common.SPT{
			Version: 12314,
			PolicyObjectBase: common.PolicyObjectBase{
				Subject: "bad domain",
			},
			CAName:          "I'm malicious CA, nice to meet you",
			LogID:           1729381,
			CertType:        0x21,
			AddedTS:         time.Now(),
			STH:             random.RandomBytesForTest(t, 32),
			PoI:             random.RandomBytesForTest(t, 32),
			STHSerialNumber: 1729381,
			Signature:       random.RandomBytesForTest(t, 32),
		},
		Reason: 1729381,
	}

	require.True(t, sprt.Equal(sprt), "SPRT Equal() error")

	rpc := &common.RPC{
		SerialNumber: 1729381,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "bad domain",
		},
		Version:            1729381,
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          random.RandomBytesForTest(t, 32),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: common.SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       random.RandomBytesForTest(t, 32),
		CASignature:        random.RandomBytesForTest(t, 32),
		SPTs:               []common.SPT{spt1, spt2},
	}

	require.True(t, rpc.Equal(rpc), "RPC Equal() error")
}

// TestJsonReadWrite: RPC -> file -> RPC, then RPC.Equal(RPC)
func TestJsonReadWrite(t *testing.T) {
	spt1 := &common.SPT{
		Version: 12313,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "hihihihihhi",
		},
		CAName:          "I'm honest CA, nice to meet you",
		LogID:           1231323,
		CertType:        0x11,
		AddedTS:         time.Now(),
		STH:             random.RandomBytesForTest(t, 32),
		PoI:             random.RandomBytesForTest(t, 32),
		STHSerialNumber: 131678,
		Signature:       random.RandomBytesForTest(t, 32),
	}

	spt2 := &common.SPT{
		Version: 12368713,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "hohohoho",
		},
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             random.RandomBytesForTest(t, 32),
		PoI:             random.RandomBytesForTest(t, 32),
		STHSerialNumber: 114378,
		Signature:       random.RandomBytesForTest(t, 32),
	}

	rpc := &common.RPC{
		SerialNumber: 1729381,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "bad domain",
		},
		Version:            1729381,
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          random.RandomBytesForTest(t, 32),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: common.SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       random.RandomBytesForTest(t, 32),
		CASignature:        random.RandomBytesForTest(t, 32),
		SPTs:               []common.SPT{*spt1, *spt2},
	}

	tempFile := path.Join(os.TempDir(), "rpctest.json")
	defer os.Remove(tempFile)
	err := common.ToJSONFile(rpc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	rpc1, err := common.JsonFileToRPC(tempFile)
	require.NoError(t, err, "Json File To RPC error")

	require.True(t, rpc.Equal(rpc1), "Json error")
}

func randomRPC(t tests.T) *common.RPC {
	return &common.RPC{
		SerialNumber: 1729381,
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "RPC CA",
		},
		Version:            1729381,
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          random.RandomBytesForTest(t, 32),
		NotBefore:          nowWithoutMonotonic(),
		NotAfter:           nowWithoutMonotonic(),
		CAName:             "RPC CA",
		SignatureAlgorithm: common.SHA256,
		TimeStamp:          nowWithoutMonotonic(),
		PRCSignature:       random.RandomBytesForTest(t, 32),
		CASignature:        random.RandomBytesForTest(t, 32),
		SPTs:               []common.SPT{*randomSPT(t), *randomSPT(t)},
	}
}

func randomRCSR(t tests.T) *common.RCSR {
	return &common.RCSR{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "subject",
		},
		Version:            6789,
		TimeStamp:          nowWithoutMonotonic(),
		PublicKeyAlgorithm: common.RSA,
		PublicKey:          random.RandomBytesForTest(t, 32),
		SignatureAlgorithm: common.SHA256,
		PRCSignature:       random.RandomBytesForTest(t, 32),
		Signature:          random.RandomBytesForTest(t, 32),
	}
}

func randomSP(t tests.T) *common.SP {
	return &common.SP{
		Policies: common.Policy{
			TrustedCA: []string{"ca1", "ca2"},
		},
		TimeStamp: nowWithoutMonotonic(),
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "domainname.com",
		},
		CAName:            "ca1",
		SerialNumber:      rand.Int(),
		CASignature:       random.RandomBytesForTest(t, 32),
		RootCertSignature: random.RandomBytesForTest(t, 32),
		SPTs: []common.SPT{
			*randomSPT(t),
			*randomSPT(t),
			*randomSPT(t),
		},
	}
}

func randomSPT(t tests.T) *common.SPT {
	return &common.SPT{
		PolicyObjectBase: common.PolicyObjectBase{
			Subject: "hohohoho",
		},
		Version:         12368713,
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         nowWithoutMonotonic(),
		STH:             random.RandomBytesForTest(t, 32),
		PoI:             random.RandomBytesForTest(t, 32),
		STHSerialNumber: 114378,
		Signature:       random.RandomBytesForTest(t, 32),
	}
}

func randomSPRT(t tests.T) *common.SPRT {
	return &common.SPRT{
		SPT:    *randomSPT(t),
		Reason: 1729381,
	}
}

func randomPSR(t tests.T) *common.PSR {
	return &common.PSR{
		Policies: common.Policy{
			TrustedCA:         []string{"one CA", "another CA"},
			AllowedSubdomains: []string{"sub1.com", "sub2.com"},
		},
		TimeStamp:         nowWithoutMonotonic(),
		DomainName:        "domain_name.com",
		RootCertSignature: random.RandomBytesForTest(t, 32),
	}
}

func randomTrillianProof(t tests.T) *trillian.Proof {
	return &trillian.Proof{
		LeafIndex: 1,
		Hashes:    [][]byte{random.RandomBytesForTest(t, 32)},
	}
}

func randomLogRootV1(t tests.T) *trilliantypes.LogRootV1 {
	return &trilliantypes.LogRootV1{
		TreeSize:       1,
		RootHash:       random.RandomBytesForTest(t, 32),
		TimestampNanos: 11,
		Revision:       3,
		Metadata:       random.RandomBytesForTest(t, 40),
	}
}

func nowWithoutMonotonic() time.Time {
	return time.Unix(time.Now().Unix(), 0)
}
