//go:build trace

package tracing

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const Enabled = true

type Tracer trace.Tracer

func init() {
	globalTracerName = os.Args[0]
	tracers = make(map[string]trace.Tracer, 1)
}

func GetTracer(name string) trace.Tracer {
	tracersMu.RLock()
	tracer, ok := tracers[name]
	tracersMu.RUnlock()
	if !ok {
		tracersMu.Lock()
		defer tracersMu.Unlock()
		tracer, ok = tracers[name]
		if !ok {
			exporter, err := newExporterGrpc(context.Background())
			if err != nil {
				panic(fmt.Sprintf("could not get a tracing exporter: %s", err))
			}
			tp := newTraceProvider(exporter, name)
			util.RegisterShutdownFunc(func() error {
				return tp.Shutdown(context.Background())
			})
			tracer = tp.Tracer(name)
			tracers[name] = tracer
		}
	}
	return tracer
}

// T is an alias for Tracer.
func T(name string) trace.Tracer {
	return GetTracer(name)
}

func SetGlobalTracerName(name string) {
	globalTracerName = name
}

// MainTracer returns the unique tracer associated with the process' entry point.
func MainTracer() trace.Tracer {
	return GetTracer(globalTracerName)
}

// TM is an alias for MainTracer.
func MT() trace.Tracer {
	return MainTracer()
}

func SetAttrInt(span trace.Span, key string, value int) {
	span.SetAttributes(attribute.Int(key, value))
}

func SetAttrString(span trace.Span, key string, value string) {
	span.SetAttributes(attribute.String(key, value))
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

// SpanIfLongTime closes, and thus brings it into existence, a given span, iff the elapsed time
// is at least the specified amount.
// This is useful to debug e.g. pipeline stages waiting for too long.
func SpanIfLongTime(
	minDuration time.Duration,
	last *timing,
	span trace.Span,
) {
	if time.Since(last.now) >= minDuration {
		span.End()
	}
	last.now = time.Now()
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

var (
	tracers          map[string]trace.Tracer
	tracersMu        sync.RWMutex
	globalTracerName string // defaults to os.Args[0]
)

type timing struct {
	now time.Time
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
		panic(fmt.Sprintf("could not get a tracing provider: %s", err))
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
