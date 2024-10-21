package main

import (
	"context"
	"fmt"
	"os"

	"github.com/netsec-ethz/fpki/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
)

var (
	in  chan tracing.Traced[string]
	out chan tracing.Traced[int]
)

func main() {
	ctx := context.Background()

	fcn, err := tracing.Initialize(ctx, "hello-world-test")
	checkErr(err)
	defer fcn()

	ctx, span := tracing.Tracer().Start(ctx, "hello-world-opentelemetry")
	defer span.End()

	// Making channels.
	{
		ctx, span := tracing.Tracer().Start(ctx, "making-channels")
		in = make(chan tracing.Traced[string])
		out = make(chan tracing.Traced[int])
		startProcessLengths(ctx)
		span.End()
	}

	if len(os.Args) != 2 {
		checkErr(fmt.Errorf("ERROR: Expecting one argument"))
	}
	helloTo := os.Args[1]
	span.SetAttributes(attribute.String("hello-to", helloTo))

	helloStr := formatString(ctx, helloTo)
	printHello(ctx, helloStr)

	l := computeLength(tracing.WrapTrace(ctx, helloStr))
	str := fmt.Sprintf("length is %d", l)
	printHello(ctx, str)

	// Now use the channels:
	in <- tracing.WrapTrace(ctx, "hello world")
	res := <-out
	fmt.Printf("channel call to length: %d\n", res.Data)

	in <- tracing.WrapTrace(ctx, helloStr)
	res = <-out
	fmt.Printf("channel call to length: %d\n", res.Data)
}

func formatString(ctx context.Context, helloTo string) string {
	_, span := tracing.Tracer().Start(ctx, "formatString")
	defer span.End()
	span.SetAttributes(
		attribute.String("event", "format-string"),
		attribute.String("value", helloTo),
	)
	helloStr := fmt.Sprintf("Hello, %s!", helloTo)
	return helloStr
}

func printHello(ctx context.Context, helloStr string) {
	_, span := tracing.Tracer().Start(ctx, "printString")
	defer span.End()
	span.SetAttributes(
		attribute.String("event", "print-string"),
	)

	fmt.Println(helloStr)
}

func computeLength(tracedStr tracing.Traced[string]) int {
	ctx, str := tracing.UnwrapTrace(tracedStr)
	_, span := tracing.Tracer().Start(ctx, "computeLengthFunc")
	defer span.End()
	return len(str)
}

func startProcessLengths(ctx context.Context) {
	_, span := tracing.Tracer().Start(ctx, "start-process-lengths")
	defer span.End()

	go func() {
		for in := range in {
			ctx, in := tracing.UnwrapTrace(in)
			ctx, span := tracing.Tracer().Start(ctx, "computeLengthAtChannel")
			span.SetAttributes(
				attribute.String("value", in),
			)

			l := len(in)
			out <- tracing.WrapTrace(ctx, l)
			span.End()
		}
	}()
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
