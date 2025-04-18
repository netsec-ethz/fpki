package tests

import (
	"context"
	"time"
)

func TestOrTimeout(t T, option timeoutOption, fcn func(T)) {
	t.Helper()
	timeout := option()

	finished := make(chan struct{})
	go func() {
		defer func() {
			finished <- struct{}{}
		}()

		fcn(t)
	}()

	select {
	case <-time.After(timeout):
		t.Logf("Timeout!! at %s: %s", time.Now().Format(time.StampNano), t.Name())
		t.FailNow()
	case <-finished:
	}
}

type timeoutOption func() time.Duration

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
