//go:build !trace

package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc/codes"
)

const Enabled = false

type Tracer interface {
	Start(context.Context, string, ...trace.SpanStartOption) (context.Context, Span)
}

func GetTracer(string) Tracer {
	return noopTracer{}
}

func T(string) Tracer {
	return GetTracer("")
}

func SetGlobalTracerName(string) {}

func MainTracer() Tracer {
	return GetTracer("")
}

func MT() Tracer {
	return MainTracer()
}

func SetAttrInt(Span, string, int)       {}
func SetAttrString(Span, string, string) {}

func Now() timing {
	return timing{}
}

func Duration(description string, since timing) attribute.KeyValue {
	return attribute.String(description, "")
}

func Since(last *timing) attribute.KeyValue {
	return Duration("duration", *last)
}

func SpanIfLongTime(time.Duration, *timing, Span) {}

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

// noopTracer provides a zero-allocation overhead.
type noopTracer struct{}

var _ Tracer = (*noopTracer)(nil)

func (noopTracer) Start(
	ctx context.Context,
	s string,
	opts ...trace.SpanStartOption,
) (context.Context, Span) {
	// It seems that noop.Span{} allocates some memory, we need our own.
	return ctx, Span{}
}

type Span struct{}

func (Span) End(options ...trace.SpanEndOption)                  {}
func (Span) AddEvent(name string, options ...trace.EventOption)  {}
func (Span) AddLink(link trace.Link)                             {}
func (Span) RecordError(err error, options ...trace.EventOption) {}
func (Span) SetStatus(codes.Code, string)                        {}
func (Span) SetName(string)                                      {}
func (Span) SetAttributes(kv ...attribute.KeyValue)              {}
func (Span) IsRecording() bool                                   { return false }
func (Span) SpanContext() trace.SpanContext {
	return trace.SpanContext{}
}
func (Span) TracerProvider() trace.TracerProvider {
	return noop.TracerProvider{}
}
