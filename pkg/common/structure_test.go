package common

import (
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEqual: Equal funcs for every structure
func TestEqual(t *testing.T) {
	rcsr := &RCSR{
		Subject:            "bandqhvdbdlwnd",
		Version:            6789,
		TimeStamp:          time.Now(),
		PublicKeyAlgorithm: RSA,
		PublicKey:          generateRandomBytes(),
		SignatureAlgorithm: SHA256,
		PRCSignature:       generateRandomBytes(),
		Signature:          generateRandomBytes(),
	}

	assert.True(t, rcsr.Equal(rcsr), "RCSR Equal() error")

	spt1 := SPT{
		Version:         12313,
		Subject:         "hihihihihhi",
		CAName:          "I'm honest CA, nice to meet you",
		LogID:           1231323,
		CertType:        0x11,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 131678,
		Signature:       generateRandomBytes(),
	}

	spt2 := SPT{
		Version:         12368713,
		Subject:         "hohohoho",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 114378,
		Signature:       generateRandomBytes(),
	}

	assert.True(t, spt1.Equal(spt1) && spt2.Equal(spt2) && !spt1.Equal(spt2) && !spt2.Equal(spt1), "SPT Equal() error")

	sprt := &SPRT{
		SPT: SPT{
			Version:         12314,
			Subject:         "bad domain",
			CAName:          "I'm malicious CA, nice to meet you",
			LogID:           1729381,
			CertType:        0x21,
			AddedTS:         time.Now(),
			STH:             generateRandomBytes(),
			PoI:             generateRandomBytes(),
			STHSerialNumber: 1729381,
			Signature:       generateRandomBytes(),
		},
		Reason: 1729381,
	}

	assert.True(t, sprt.Equal(sprt), "SPRT Equal() error")

	rpc := &RPC{
		SerialNumber:       1729381,
		Subject:            "bad domain",
		Version:            1729381,
		PublicKeyAlgorithm: RSA,
		PublicKey:          generateRandomBytes(),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       generateRandomBytes(),
		CASignature:        generateRandomBytes(),
		SPTs:               []SPT{spt1, spt2},
	}

	assert.True(t, rpc.Equal(rpc), "RPC Equal() error")
}

// TestJsonReadWrite: RPC -> file -> RPC, then RPC.Equal(RPC)
func TestJsonReadWrite(t *testing.T) {
	spt1 := &SPT{
		Version:         12313,
		Subject:         "hihihihihhi",
		CAName:          "I'm honest CA, nice to meet you",
		LogID:           1231323,
		CertType:        0x11,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 131678,
		Signature:       generateRandomBytes(),
	}

	spt2 := &SPT{
		Version:         12368713,
		Subject:         "hohohoho",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         time.Now(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 114378,
		Signature:       generateRandomBytes(),
	}

	rpc := &RPC{
		SerialNumber:       1729381,
		Subject:            "bad domain",
		Version:            1729381,
		PublicKeyAlgorithm: RSA,
		PublicKey:          generateRandomBytes(),
		NotBefore:          time.Now(),
		NotAfter:           time.Now(),
		CAName:             "bad domain",
		SignatureAlgorithm: SHA256,
		TimeStamp:          time.Now(),
		PRCSignature:       generateRandomBytes(),
		CASignature:        generateRandomBytes(),
		SPTs:               []SPT{*spt1, *spt2},
	}

	tempFile := path.Join(os.TempDir(), "rpctest.json")
	defer os.Remove(tempFile)
	err := ToJSONFile(rpc, tempFile)
	require.NoError(t, err, "Json Struct To File error")

	rpc1, err := JsonFileToRPC(tempFile)
	require.NoError(t, err, "Json File To RPC error")

	assert.True(t, rpc.Equal(rpc1), "Json error")
}

// TestSingleObject checks that the structure types in the test cases can be converted to JSON and
// back, using the functions ToJSON and FromJSON.
// It checks after deserialization if the objects are equal.
func TestSingleObject(t *testing.T) {
	cases := map[string]struct {
		data any
	}{
		"rcsr": {
			data: &RCSR{
				Subject:            "bandqhvdbdlwnd",
				Version:            6789,
				TimeStamp:          time.Unix(111222323, 0),
				PublicKeyAlgorithm: RSA,
				PublicKey:          generateRandomBytes(),
				SignatureAlgorithm: SHA256,
				PRCSignature:       generateRandomBytes(),
				Signature:          generateRandomBytes(),
			},
		},
		"rpc": {
			data: &RPC{
				SerialNumber:       1729381,
				Subject:            "bad domain",
				Version:            1729381,
				PublicKeyAlgorithm: RSA,
				PublicKey:          generateRandomBytes(),
				NotBefore:          nowWithoutMonotonic(),
				NotAfter:           nowWithoutMonotonic(),
				CAName:             "bad domain",
				SignatureAlgorithm: SHA256,
				TimeStamp:          nowWithoutMonotonic(),
				PRCSignature:       generateRandomBytes(),
				CASignature:        generateRandomBytes(),
				SPTs:               []SPT{*randomSPT(), *randomSPT()},
			},
		},
		"spt": {
			data: &SPT{
				Version:         11,
				Subject:         "hihihihihhi",
				CAName:          "this is the CA name",
				LogID:           42,
				CertType:        0x11,
				AddedTS:         time.Unix(1234, 0),
				STH:             generateRandomBytes(),
				PoI:             generateRandomBytes(),
				STHSerialNumber: 131678,
				Signature:       generateRandomBytes(),
			},
		},
		"sprt": {
			data: &SPRT{
				SPT: SPT{
					Version:         12314,
					Subject:         "bad domain",
					CAName:          "I'm malicious CA, nice to meet you",
					LogID:           1729381,
					CertType:        0x21,
					AddedTS:         nowWithoutMonotonic(),
					STH:             generateRandomBytes(),
					PoI:             generateRandomBytes(),
					STHSerialNumber: 1729381,
					Signature:       generateRandomBytes(),
				},
				Reason: 1729381,
			},
		},
		"sp": {
			data: &SP{
				Policies: Policy{
					TrustedCA:         []string{"one CA", "another CA"},
					AllowedSubdomains: []string{"sub1.com", "sub2.com"},
				},
				TimeStamp:         nowWithoutMonotonic(),
				Subject:           "sp subject",
				CAName:            "one CA",
				SerialNumber:      1234,
				CASignature:       generateRandomBytes(),
				RootCertSignature: generateRandomBytes(),
				SPTs:              []SPT{*randomSPT(), *randomSPT(), *randomSPT()},
			},
		},
		"psr": {
			data: &PSR{
				Policies: Policy{
					TrustedCA:         []string{"one CA", "another CA"},
					AllowedSubdomains: []string{"sub1.com", "sub2.com"},
				},
				TimeStamp:         nowWithoutMonotonic(),
				DomainName:        "domain_name.com",
				RootCertSignature: generateRandomBytes(),
			},
		},
	}

	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			expectedType := reflect.TypeOf(tc.data) // type will be a pointer to RPC, etc.
			d, err := ToJSON(tc.data)
			t.Logf("JSON: %s", string(d))
			require.NoError(t, err)

			o, err := FromJSON(d)
			require.NoError(t, err)
			require.NotNil(t, o)
			require.Equal(t, tc.data, o)

			gotType := reflect.TypeOf(o)
			require.Equal(t, expectedType, gotType)
		})
	}
}

func randomSPT() *SPT {
	return &SPT{
		Version:         12368713,
		Subject:         "hohohoho",
		CAName:          "I'm malicious CA, nice to meet you",
		LogID:           1324123,
		CertType:        0x21,
		AddedTS:         nowWithoutMonotonic(),
		STH:             generateRandomBytes(),
		PoI:             generateRandomBytes(),
		STHSerialNumber: 114378,
		Signature:       generateRandomBytes(),
	}
}

func nowWithoutMonotonic() time.Time {
	return time.Unix(time.Now().Unix(), 0)
}
