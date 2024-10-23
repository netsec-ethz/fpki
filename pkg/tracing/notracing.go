//go:build !trace

package tracing

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

var tracer trace.Tracer

func Initialize(ctx context.Context, serviceName string) (func() error, error) {
	tracer = noop.Tracer{}
	return func() error { return nil }, nil
}

func Tracer() trace.Tracer {
	return tracer
}

func T() trace.Tracer {
	return Tracer()
}

type timing struct{}

func Now() timing {
	return timing{}
}

func Duration(description string, since timing) attribute.KeyValue {
	return attribute.String(description, "")
}

func Since(last *timing) attribute.KeyValue {
	return Duration("duration", *last)
}

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
