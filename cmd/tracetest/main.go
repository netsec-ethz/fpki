package main

import (
	"context"
	"fmt"
	"os"

	tr "github.com/netsec-ethz/fpki/pkg/tracing"
	"github.com/netsec-ethz/fpki/pkg/util"
	"go.opentelemetry.io/otel/attribute"
)

var (
	in  chan tr.Traced[string]
	out chan tr.Traced[int]
)

func main() {
	ctx := context.Background()
	defer func() {
		err := util.ShutdownFunction()
		checkErr(err)
	}()

	tr.SetGlobalTracerName("tracetest")
	tracer := tr.MainTracer()
	ctx, span := tracer.Start(ctx, "main")
	defer span.End()

	// Making channels.
	{
		ctx, span := tracer.Start(ctx, "making-channels")
		in = make(chan tr.Traced[string])
		out = make(chan tr.Traced[int])
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

	l := computeLength(tr.WrapTrace(ctx, helloStr))
	str := fmt.Sprintf("length is %d", l)
	printHello(ctx, str)

	// Now use the channels:
	in <- tr.WrapTrace(ctx, "hello world")
	res := <-out
	fmt.Printf("channel call to length: %d\n", res.Data)

	in <- tr.WrapTrace(ctx, helloStr)
	res = <-out
	fmt.Printf("channel call to length: %d\n", res.Data)
}

func formatString(ctx context.Context, helloTo string) string {
	_, span := tr.MainTracer().Start(ctx, "formatString")
	defer span.End()
	span.SetAttributes(
		attribute.String("event", "format-string"),
		attribute.String("value", helloTo),
	)
	helloStr := fmt.Sprintf("Hello, %s!", helloTo)
	return helloStr
}

func printHello(ctx context.Context, helloStr string) {
	_, span := tr.MT().Start(ctx, "printString")
	defer span.End()
	span.SetAttributes(
		attribute.String("event", "print-string"),
	)

	fmt.Println(helloStr)
}

func computeLength(tracedStr tr.Traced[string]) int {
	ctx, str := tr.UnwrapTrace(tracedStr)
	_, span := tr.MainTracer().Start(ctx, "computeLengthFunc")
	defer span.End()
	return len(str)
}

func startProcessLengths(ctx context.Context) {
	tracer := tr.T("length-processor")
	_, span := tracer.Start(ctx, "start-process-lengths")
	defer span.End()

	go func() {
		for in := range in {
			ctx, in := tr.UnwrapTrace(in)
			ctx, span := tracer.Start(ctx, "computeLengthAtChannel")
			span.SetAttributes(
				attribute.String("value", in),
			)

			l := len(in)
			out <- tr.WrapTrace(ctx, l)
			span.End()
		}
	}()
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
