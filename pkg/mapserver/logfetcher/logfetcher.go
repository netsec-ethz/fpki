package logfetcher

import (
	"context"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

type Fetcher interface {
	Initialize(updateStartTime time.Time) error
	URL() string
	GetCurrentState(ctx context.Context, origState State) (State, error)
	StartFetching(startIndex, endIndex int64)
	StopFetching()

	// Like with sql.Rows.Next()
	NextBatch(ctx context.Context) bool
	// Like sql.Rows.Scan(...) also returns the number of certificates in the batch that were removed (e.g., due to their expiration time)
	ReturnNextBatch() ([]*ctx509.Certificate, [][]*ctx509.Certificate, int, error)
}

type State struct {
	Size uint64
	// STH is the signed tree head of the server.
	STH []byte
}

type result struct {
	certs   []*ctx509.Certificate
	chains  [][]*ctx509.Certificate
	expired int
	err     error
}
