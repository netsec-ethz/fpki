package util

import (
	"fmt"
	"strings"
)

// ErrorsCoalesce coalesces a number of errors into only one. Nil errors are ignored, and errors
// with the same message are deduplicated.
// If the errors to coalesce contain themselves an already coalesced error, its children will be
// added (instead of nesting coalesced errors).
// If the final collection has only one error, the error
// message will be that of the original error. Otherwise, an indication of how many errors will
// be given, with the text of those errors.
func ErrorsCoalesce(errs ...error) error {
	cerr := CoalescedErrors{}
	for _, err := range errs {
		cerr.addError(err)

	}
	if len(cerr.Errs) == 0 {
		return nil
	}
	return cerr
}

type CoalescedErrors struct {
	Errs []error
}

var _ error = CoalescedErrors{}

func (e CoalescedErrors) Error() string {
	switch len(e.Errs) {
	case 0:
		return ""
	case 1:
		return e.Errs[0].Error()
	}

	// When there multiple errors, write a line with each one of them and returned the coalesced one.
	msgs := make([]string, len(e.Errs))
	for i, err := range e.Errs {
		msgs[i] = err.Error()
	}
	return fmt.Sprintf("multiple (%d) errors:\n%s", len(msgs), strings.Join(msgs, "\n"))
}

func (e CoalescedErrors) Unwrap() []error {
	return e.Errs
}

// addError adds an error iff it is not already present (same message) in this object.
func (e *CoalescedErrors) addError(err error) {
	if err == nil {
		return
	}
	switch v := err.(type) {
	case CoalescedErrors:
		for _, child := range v.Errs {
			e.addError(child)
		}
	default:
		for _, existing := range e.Errs {
			if existing.Error() == err.Error() {
				return
			}
		}
		e.Errs = append(e.Errs, err)
	}
}
