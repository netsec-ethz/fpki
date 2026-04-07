package util

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorsCoalesceNilReturnsNil(t *testing.T) {
	require.NoError(t, ErrorsCoalesce(nil, nil))
}

// TestErrorsCoalesceSingleErrorKeepsMessage verifies that coalescing a single
// non-nil error preserves its original message.
func TestErrorsCoalesceSingleErrorKeepsMessage(t *testing.T) {
	err := errors.New("only one")

	got := ErrorsCoalesce(err)

	require.EqualError(t, got, "only one")
}

// TestErrorsCoalesceDeduplicatesIdenticalMessages verifies that separate error
// values with the same rendered message collapse to one aggregated entry.
func TestErrorsCoalesceDeduplicatesIdenticalMessages(t *testing.T) {
	first := errors.New("same")
	second := errors.New("same")

	got := ErrorsCoalesce(first, second)

	coalesced, ok := got.(CoalescedErrors)
	require.True(t, ok)
	require.Len(t, coalesced.Errs, 1)
	require.EqualError(t, got, "same")
}

// TestErrorsCoalesceFlattensAndDeduplicatesNestedCoalescedErrors verifies that
// nested coalesced errors are flattened and deduplicated while preserving
// first-seen order in the final message.
func TestErrorsCoalesceFlattensAndDeduplicatesNestedCoalescedErrors(t *testing.T) {
	first := errors.New("first")
	duplicateFirst := errors.New("first")
	second := errors.New("second")

	got := ErrorsCoalesce(
		ErrorsCoalesce(first, duplicateFirst),
		ErrorsCoalesce(second),
	)

	coalesced, ok := got.(CoalescedErrors)
	require.True(t, ok)
	require.Len(t, coalesced.Errs, 2)
	require.EqualError(t, got, "multiple (2) errors:\nfirst\nsecond")
}

// TestErrorsCoalesceSupportsErrorsIsThroughUnwrap verifies that aggregated
// errors expose their children through Unwrap so errors.Is can match them.
func TestErrorsCoalesceSupportsErrorsIsThroughUnwrap(t *testing.T) {
	got := ErrorsCoalesce(context.Canceled, errors.New("other"))

	require.ErrorIs(t, got, context.Canceled)
	require.EqualError(t, got, "multiple (2) errors:\ncontext canceled\nother")
}
