package tests

import (
	"context"
	"testing"
	"time"
)

func TestOrTimeout(t *testing.T, fcn func(T), timeoutFunc timeoutFcn) {
	t.Helper()
	timeout := timeoutFunc()

	finished := make(chan struct{})
	go func() {
		defer func() {
			t.Logf("Test finished: %s", t.Name())
			finished <- struct{}{}
		}()

		fcn(t)
	}()

	select {
	case <-time.After(timeout):
		t.Errorf("Timeout!!: %s", t.Name())
	case <-finished:
	}
}

type timeoutFcn func() time.Duration

func WithTimeout(timeout time.Duration) func() time.Duration {
	return func() time.Duration {
		return timeout
	}
}

func WithContext(ctx context.Context) func() time.Duration {
	return func() time.Duration {
		deadline, ok := ctx.Deadline()
		if !ok {
			return time.Duration(-1)
		}
		return time.Until(deadline)
	}
}
