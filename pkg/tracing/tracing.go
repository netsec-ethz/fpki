//go:build trace

package tracing

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var tracer trace.Tracer

// Initialize enables tracing by using the OTLP exporter (e.g. Jaeger).
func Initialize(ctx context.Context, serviceName string) (func() error, error) {
	exporter, err := newExporterGrpc(ctx)
	if err != nil {
		return nil, err
	}

	tp := newTraceProvider(exporter, serviceName)
	otel.SetTracerProvider(tp)

	tracer = tp.Tracer("fpki")

	atExit := func() error {
		return tp.Shutdown(ctx)
	}

	return atExit, nil
}

// Tracer returns the current tracer. If not initialized, it will be nil.
func Tracer() trace.Tracer {
	return tracer
}

// T is an alias for Tracer()
func T() trace.Tracer {
	return Tracer()
}

type timing struct {
	now time.Time
}

func Now() timing {
	return timing{time.Now()}
}

func Duration(description string, since timing) attribute.KeyValue {
	return attribute.String(description, time.Since(since.now).String())
}

func Since(last *timing) attribute.KeyValue {
	kv := Duration("duration", *last)
	last.now = time.Now()
	return kv
}

type Traced[T any] struct {
	Traces traceDetails
	Data   T
}

func WrapTrace[T any](ctx context.Context, value T) Traced[T] {
	return Traced[T]{
		Data:   value,
		Traces: extractTraceDetails(ctx),
	}
}

func UnwrapTrace[T any](traced Traced[T]) (context.Context, T) {
	return newTracingContext(traced.Traces), traced.Data
}

func newExporterHttp(ctx context.Context) (sdktrace.SpanExporter, error) {
	return otlptracehttp.New(
		ctx,
		otlptracehttp.WithInsecure(),
	)
}

func newExporterGrpc(ctx context.Context) (sdktrace.SpanExporter, error) {
	return otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithInsecure(),
	)
}

func newTraceProvider(exp sdktrace.SpanExporter, serviceName string) *sdktrace.TracerProvider {
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)

	if err != nil {
		panic(err)
	}

	return sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(r),
	)
}

// Code based on comments from:
// https://www.reddit.com/r/golang/comments/1d1srg3/tracing_async_jobs_across_multiple_go_components

type ctxKey struct{}

type traceDetails struct {
	TraceID trace.TraceID
	SpanID  trace.SpanID
}

// injectTraceDetails adds TraceDetails to the context.
func injectTraceDetails(ctx context.Context, details traceDetails) context.Context {
	return context.WithValue(ctx, ctxKey{}, details)
}

// extractTraceDetails retrieves TraceDetails from the context.
// If not found, it falls back to extracting a SpanContext and converting it.
func extractTraceDetails(ctx context.Context) traceDetails {
	if traceDetails, ok := ctx.Value(ctxKey{}).(traceDetails); ok {
		return traceDetails
	}
	spanCtx := trace.SpanContextFromContext(ctx)
	return traceDetails{
		TraceID: spanCtx.TraceID(),
		SpanID:  spanCtx.SpanID(),
	}
}

// newTracingContext creates a new context with a SpanContext derived from TraceDetails.
func newTracingContext(details traceDetails) context.Context {
	spanCtx := createSpanContextFromTraceDetails(details)
	return trace.ContextWithSpanContext(context.Background(), spanCtx)
}

// createSpanContextFromTraceDetails creates a SpanContext from TraceDetails.
func createSpanContextFromTraceDetails(details traceDetails) trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    details.TraceID,
		SpanID:     details.SpanID,
		TraceFlags: trace.FlagsSampled,
		TraceState: trace.TraceState{},
		Remote:     false,
	})
}
