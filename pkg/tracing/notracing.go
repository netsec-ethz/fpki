//go:build !trace

package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const Enabled = false

func Tracer(string) trace.Tracer {
	return noop.Tracer{}
}

func T(string) trace.Tracer {
	return Tracer("")
}

func SetGlobalTracerName(string) {}

func MainTracer() trace.Tracer {
	return Tracer("")
}

func MT() trace.Tracer {
	return MainTracer()
}

func Now() timing {
	return timing{}
}

func Duration(description string, since timing) attribute.KeyValue {
	return attribute.String(description, "")
}

func Since(last *timing) attribute.KeyValue {
	return Duration("duration", *last)
}

func SpanIfLongTime(time.Duration, *timing, trace.Span) {}

type Traced[T any] struct {
	Data T
}

func WrapTrace[T any](ctx context.Context, value T) Traced[T] {
	return Traced[T]{
		Data: value,
	}
}

func UnwrapTrace[T any](traced Traced[T]) (context.Context, T) {
	return context.Background(), traced.Data
}

type timing struct{}
