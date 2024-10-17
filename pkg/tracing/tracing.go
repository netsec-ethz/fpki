package tracing

import (
	"context"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// -------------------------------------------------------------------------------------------

var tracer trace.Tracer

func newExporter(ctx context.Context) /* (someExporter.Exporter, error) */ {
	// Your preferred exporter: console, jaeger, zipkin, OTLP, etc.

}

func newTraceProvider(exp sdktrace.SpanExporter) *sdktrace.TracerProvider {
	// Ensure default SDK resources and the required service name are set.
	r, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("ExampleService"),
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

// -------------------------------------------------------------------------------------------

// From https://www.reddit.com/r/golang/comments/1d1srg3/tracing_async_jobs_across_multiple_go_components/

type ctxKey string

const traceDetailsKey = ctxKey("traceDetails")

type TraceDetails struct {
	TraceID trace.TraceID
	SpanID  trace.SpanID
	User    string // deleteme
}

type Traced[T any] struct {
	Traces TraceDetails
	Data   T
}

func EnrichWithTraceDetails[T any](data T, traceDetails TraceDetails) Traced[T] {
	return Traced[T]{
		Traces: traceDetails,
		Data:   data,
	}
}

// InjectTraceDetails adds TraceDetails to the context.
func InjectTraceDetails(ctx context.Context, details TraceDetails) context.Context {
	return context.WithValue(ctx, traceDetailsKey, details)
}

// ExtractTraceDetails retrieves TraceDetails from the context.
// If not found, it falls back to extracting a SpanContext and converting it.
func ExtractTraceDetails(ctx context.Context) TraceDetails {
	if traceDetails, ok := ctx.Value(traceDetailsKey).(TraceDetails); ok {
		return traceDetails
	}
	return traceDetailsFromSpanContext(trace.SpanContextFromContext(ctx))
}

// NewTracingContext creates a new context with a SpanContext derived from TraceDetails.
func NewTracingContext(details TraceDetails) context.Context {
	spanCtx := createSpanContextFromTraceDetails(details)
	return trace.ContextWithSpanContext(context.Background(), spanCtx)
}

// traceDetailsFromSpanContext creates TraceDetails from a SpanContext.
func traceDetailsFromSpanContext(ctx trace.SpanContext) TraceDetails {
	return TraceDetails{
		TraceID: ctx.TraceID(),
		SpanID:  ctx.SpanID(),
		User:    "", // User is empty as there's no user data in SpanContext
	}
}

// createSpanContextFromTraceDetails creates a SpanContext from TraceDetails.
func createSpanContextFromTraceDetails(details TraceDetails) trace.SpanContext {
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    details.TraceID,
		SpanID:     details.SpanID,
		TraceFlags: trace.FlagsSampled,
		TraceState: trace.TraceState{},
		Remote:     false,
	})
}
