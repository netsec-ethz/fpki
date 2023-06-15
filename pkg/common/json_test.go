package common_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/tests/random"
)

// TestPolicyObjects checks that the structure types in the test cases can be converted to JSON and
// back, using the functions ToJSON and FromJSON.
// It checks after deserialization that the objects are equal.
func TestPolicyObjects(t *testing.T) {
	cases := map[string]struct {
		data any
	}{
		"rpcPtr": {
			data: random.RandomRPC(t),
		},
		"rpcValue": {
			data: *random.RandomRPC(t),
		},
		"rcsr": {
			data: random.RandomRCSR(t),
		},
		"sp": {
			data: random.RandomSP(t),
		},
		"spt": {
			data: *random.RandomSPT(t),
		},
		"list": {
			data: []any{
				random.RandomRPC(t),
				random.RandomRCSR(t),
				random.RandomSP(t),
				random.RandomSPRT(t),
				random.RandomPSR(t),
				randomTrillianProof(t),
				randomLogRootV1(t),
			},
		},
		"list_embedded": {
			data: []any{
				random.RandomRPC(t),
				[]any{
					random.RandomSP(t),
					random.RandomSPT(t),
				},
				[]any{
					randomTrillianProof(t),
					randomTrillianProof(t),
				},
			},
		},
		"multiListPtr": {
			data: &[]any{
				random.RandomRPC(t),
				*random.RandomRPC(t),
				[]any{
					random.RandomSP(t),
					*random.RandomSP(t),
					&[]any{
						random.RandomSPT(t),
						*random.RandomSPT(t),
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
			data, err := common.ToJSON(tc.data)
			require.NoError(t, err)
			// Deserialize.
			deserialized, err := common.FromJSON(data, common.WithSkipCopyJSONIntoPolicyObjects)
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
			obj:           random.RandomRPC(t),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				rpc := obj.(*common.RPC)
				return [][]byte{rpc.RawJSON}
			},
		},
		"spPtr": {
			obj:           random.RandomSP(t),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				sp := obj.(*common.SP)
				return [][]byte{sp.RawJSON}
			},
		},
		"spValue": {
			obj:           *random.RandomSP(t),
			rawElemsCount: 1,
			getRawElemsFcn: func(obj any) [][]byte {
				sp := obj.(common.SP)
				return [][]byte{sp.RawJSON}
			},
		},
		"list": {
			obj: []any{
				random.RandomSP(t),
				random.RandomRPC(t),
			},
			rawElemsCount: 2,
			getRawElemsFcn: func(obj any) [][]byte {
				l := obj.([]any)
				return [][]byte{
					l[0].(*common.SP).RawJSON,
					l[1].(*common.RPC).RawJSON,
				}
			},
		},
	}
	for name, tc := range testCases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			// Serialize.
			data, err := common.ToJSON(tc.obj)
			require.NoError(t, err)
			// Deserialize.
			obj, err := common.FromJSON(data)
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
