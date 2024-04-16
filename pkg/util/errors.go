package util

import (
	"fmt"
	"strings"
)

func ErrorsCoalesce(errs []error) error {
	// First find if there is any error at all (common case is "no").
	nonNilErrors := make([]error, 0, len(errs))
	for _, err := range errs {
		if err != nil {
			nonNilErrors = append(nonNilErrors, err)
		}
	}
	if len(nonNilErrors) == 0 {
		return nil
	}

	// When there are errors, write a line with each one of them and returned the coalesced one.
	msgs := make([]string, len(nonNilErrors))
	for i, err := range nonNilErrors {
		msgs[i] = err.Error()
	}
	return fmt.Errorf("multiple (%d) errors:\n%s", len(msgs), strings.Join(msgs, "\n"))
}
