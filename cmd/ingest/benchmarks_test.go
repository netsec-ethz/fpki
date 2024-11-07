package main

import (
	"context"
	"encoding/csv"
	"math"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

// BenchmarkCsvSplit runs in 1_610_052_919 ns/op (100006 lines), equivalent to 62116 lines/sec.
func BenchmarkCsvSplit(b *testing.B) {
	ctx := context.Background()
	p := &Processor{
		Ctx:        ctx,
		Manager:    getManager(b),
		NumToChain: 1,
	}

	w := NewCsvSplitWorker(p)
	w.Prepare(ctx)

	// Mock linking.
	w.OutgoingChs[0] = make(chan line)
	w.NextErrChs[0] = make(chan error)

	// Mock incoming.
	go func() {
		w.IncomingChs[0] <- (&util.GzFile{}).WithFile("testdata/0-100005.gz")
		close(w.IncomingChs[0])
	}()

	b.ResetTimer()
	// Resume the stage.
	w.Resume(ctx)
	for l := range w.OutgoingChs[0] {
		_ = l
	}

	close(w.NextErrChs[0])
	<-w.ErrCh
}

// BenchmarkLineToChain runs in 6_967_239_873 ns/op (100000 chains), equivalent to 14353 chains/sec.
func BenchmarkLineToChain(b *testing.B) {
	ctx := context.Background()
	p := &Processor{
		Ctx:        ctx,
		Manager:    getManager(b),
		NumToChain: 1,
	}

	w := NewLineToChainWorker(p, 0)
	w.Prepare(ctx)

	// Mock linking.
	w.OutgoingChs[0] = make(chan certChain)
	w.NextErrChs[0] = make(chan error)

	// Mock incoming.
	lines := getLines(b, "testdata/0-100005.gz", 100000)
	go func() {
		for _, l := range lines {
			w.IncomingChs[0] <- l
		}
		close(w.IncomingChs[0])
	}()

	b.ResetTimer()
	// Resume the stage.
	w.Resume(ctx)
	count := 0
	for range w.OutgoingChs[0] {
		count++
	}
	b.Logf("read %d chains", count)

	close(w.NextErrChs[0])
	<-w.ErrCh
}

// BenchmarkChainsToCert runs in 699.508518 ms (100K chains, 100617 certs), equivalent to 144K certs/sec.
func BenchmarkChainsToCert(b *testing.B) {
	b.Logf("running with N=%d", b.N)
	ctx := context.Background()
	p := &Processor{
		Ctx:        ctx,
		Manager:    getManager(b),
		NumToChain: 1,
	}

	w := NewChainToCertWorker(0)
	w.Prepare(ctx)

	// Mock linking.
	w.OutgoingChs[0] = make(chan updater.Certificate)
	w.NextErrChs[0] = make(chan error)

	// Mock incoming.
	N := min(b.N, 100_000)
	chains := getChains(b, p, getLines(b, "testdata/0-100005.gz", N))
	go func() {
		for _, chain := range chains {
			w.IncomingChs[0] <- chain
		}
		close(w.IncomingChs[0])
	}()

	b.ResetTimer()
	// Resume the stage.
	w.Resume(ctx)
	count := 0
	for range w.OutgoingChs[0] {
		count++
	}
	b.Logf("read %d certificates in %s", count, b.Elapsed().String())

	close(w.NextErrChs[0])
	<-w.ErrCh
}

// BenchmarkCertSink runs in ~ 4.87us for 100617 certs, equivalent to millions of certs/sec.
func BenchmarkCertSink(b *testing.B) {
	b.Logf("running with N=%d", b.N)
	ctx := context.Background()
	p := &Processor{
		Ctx:        ctx,
		Manager:    getManager(b),
		NumToChain: 1,
	}

	w := p.createCertificateSink()
	w.Prepare(ctx)

	// Mock incoming.
	N := min(b.N, 100_000)
	certs := getCerts(b, getChains(b, p, getLines(b, "testdata/0-100005.gz", N)))
	go func() {
		for _, cert := range certs {
			w.IncomingChs[0] <- cert
		}
		close(w.IncomingChs[0])
	}()

	b.ResetTimer()
	// Resume the stage.
	w.Resume(ctx)
	b.Logf("read %d certificates in %s", len(certs), b.Elapsed().String())

	<-w.ErrCh
}

func getManager(t tests.T) *updater.Manager {
	m, err := updater.NewManager(1, nil, math.MaxInt, math.MaxUint64, nil, time.Hour, nil)
	require.NoError(t, err)
	return m
}

func getLines(t tests.T, filename string, count int) []line {
	t.Logf("getting %d lines", count)
	gz := (&util.GzFile{}).WithFile(filename)
	r, err := gz.Open()
	require.NoError(t, err)
	csvr := csv.NewReader(r)
	lines := make([]line, count)
	for i := 0; i < count; i++ {
		fields, err := csvr.Read()
		require.NoError(t, err)
		lines[i].fields = fields
	}

	return lines
}

func getChains(t tests.T, p *Processor, lines []line) []certChain {
	t.Logf("getting %d chains", len(lines))
	w := NewLineToChainWorker(p, 0)
	chains := make([]certChain, 0, len(lines))
	for _, l := range lines {
		chain, err := w.parseLine(p, &l)
		require.NoError(t, err)
		chains = append(chains, *chain)
	}

	return chains
}

func getCerts(t tests.T, chains []certChain) []updater.Certificate {
	t.Logf("getting certificates for %d chains", len(chains))
	certs := make([]updater.Certificate, 0)
	for _, c := range chains {
		c := c
		certs = append(certs,
			updater.CertificatesFromChains((*updater.CertWithChainData)(&c))...,
		)
	}

	return certs
}
