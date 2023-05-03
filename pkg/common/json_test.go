package common

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/trillian"
	trilliantypes "github.com/google/trillian/types"
	"github.com/stretchr/testify/require"
)

// TestPolicyObjects checks that the structure types in the test cases can be converted to JSON and
// back, using the functions ToJSON and FromJSON.
// It checks after deserialization that the objects are equal.
func TestPolicyObjects(t *testing.T) {
	cases := map[string]struct {
		data any
	}{
		"rpcPtr": {
			data: randomRPC(),
		},
		"rpcValue": {
			data: *randomRPC(),
		},
		"rcsr": {
			data: randomRCSR(),
		},
		"sp": {
			data: randomSP(),
		},
		"spt": {
			data: *randomSPT(),
		},
		"list": {
			data: []any{
				randomRPC(),
				randomRCSR(),
				randomSP(),
				randomSPRT(),
				randomPSR(),
				randomTrillianProof(),
				randomLogRootV1(),
			},
		},
		"list_embedded": {
			data: []any{
				randomRPC(),
				[]any{
					randomSP(),
					randomSPT(),
				},
				[]any{
					randomTrillianProof(),
					randomTrillianProof(),
				},
			},
		},
		"multiListPtr": {
			data: &[]any{
				randomRPC(),
				*randomRPC(),
				[]any{
					randomSP(),
					*randomSP(),
					&[]any{
						randomSPT(),
						*randomSPT(),
					},
				},
			},
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Serialize.
			data, err := ToJSON(tc.data)
			require.NoError(t, err)
			// Deserialize.
			deserialized, err := FromJSON(data, WithSkipCopyJSONIntoPolicyObjects)
			require.NoError(t, err)
			// Compare.
			require.Equal(t, tc.data, deserialized)
		})
	}
}

// TestPolicyObjectBaseRaw checks that the Raw field of the PolicyObjectBase for any PolicyObject
// that is rebuilt using our functions contains the original JSON.
func TestPolicyObjectBaseRaw(t *testing.T) {
	// Empty RPC to JSON.
	testCases := map[string]struct {
		obj            any                    // Thing to serialize and deserialize and check Raw.
		rawElemsCount  int                    // Expected number of Raw elements inside.
		getRawElemsFcn func(obj any) [][]byte // Return the Raw components of this thing.
	}{
		"rpc": {
			obj:           randomRPC(),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				rpc := obj.(*RPC)
				return [][]byte{rpc.RawJSON}
			},
		},
		"spPtr": {
			obj:           randomSP(),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				sp := obj.(*SP)
				return [][]byte{sp.RawJSON}
			},
		},
		"spValue": {
			obj:           *randomSP(),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				sp := obj.(SP)
				return [][]byte{sp.RawJSON}
			},
		},
		"list": {
			obj: []any{
				randomSP(),
				randomRPC(),
			},
			rawElemsCount: 2,
			getRawElemsFcn: func(obj any) [][]byte {
				l := obj.([]any)
				return [][]byte{
					l[0].(*SP).RawJSON,
					l[1].(*RPC).RawJSON,
				}
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Serialize.
			data, err := ToJSON(tc.obj)
			require.NoError(t, err)
			// Deserialize.
			obj, err := FromJSON(data)
			require.NoError(t, err)
			t.Logf("This object is of type %T", obj)
			raws := tc.getRawElemsFcn(obj)
			require.Len(t, raws, tc.rawElemsCount)
			// Log facts about this object for debug purposes in case the test fails.
			allRaw := make([]string, tc.rawElemsCount)
			for i, raw := range raws {
				allRaw[i] = string(raw)
			}
			t.Logf("This object has this JSON:\n----------\n%s\n----------",
				strings.Join(allRaw, ""))
			// Each one of the raw bytes should be a substring of the JSON data, in order.
			offset := 0
			for i, raw := range raws {
				require.NotEmpty(t, raw, "bad raw JSON for subelement %d", i)
				idx := bytes.Index(data[offset:], raw) // if not found, -1 is returned
				require.GreaterOrEqual(t, idx, 0)
				offset = idx
			}
			// We could check that the complete JSON is an aggregation of the elements' JSON plus
			// maybe some "list" indicator (sometimes).
		})
	}
}

func randomTrillianProof() *trillian.Proof {
	return &trillian.Proof{
		LeafIndex: 1,
		Hashes:    generateRandomBytesArray(),
	}
}

func randomLogRootV1() *trilliantypes.LogRootV1 {
	return &trilliantypes.LogRootV1{
		TreeSize:       1,
		RootHash:       generateRandomBytes(),
		TimestampNanos: 11,
		Revision:       3,
		Metadata:       generateRandomBytes(),
	}
}
