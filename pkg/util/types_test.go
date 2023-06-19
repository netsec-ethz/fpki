package util

import (
	"testing"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/stretchr/testify/require"
)

func TestToTypedSlice(t *testing.T) {
	// slice of int
	{
		s := []any{1, 2}
		r, err := ToTypedSlice[int](s)
		require.NoError(t, err)
		require.Equal(t, []int{1, 2}, r)
	}

	// slice of *common.RPC
	{
		orig := []*common.RPC{
			{},
			{},
		}
		orig[0].RawVersion = 1
		orig[1].RawVersion = 2
		s := make([]any, len(orig))
		for i, e := range orig {
			s[i] = e
		}
		r, err := ToTypedSlice[*common.RPC](s)
		require.NoError(t, err)
		require.Equal(t, orig, r)
	}
}

func TestToType(t *testing.T) {
	// *common.RPC
	{
		orig := &common.RPC{}
		orig.RawSubject = "a.com"
		orig.RawVersion = 1
		e := any(orig)
		r, err := ToType[*common.RPC](e)
		require.NoError(t, err)
		require.Equal(t, orig, r)
	}
}
