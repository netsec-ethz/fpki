package util

import (
	"fmt"
	"strings"
)

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

func (e *CoalescedErrors) addError(err error) {
	if err == nil {
		return
	}
	switch v := err.(type) {
	case CoalescedErrors:
		e.Errs = append(e.Errs, v.Errs...)
	default:
		e.Errs = append(e.Errs, err)
	}
}
