package main

import (
	"fmt"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
)

type lineToChainPtrWorker struct {
	*pip.Stage[line, *certChain]

	now   time.Time
	cache cache.Cache // IDs of certificates already seen
}

// NewLineToChainPtrWorker creates a stage that emits pointers to parsed certificate chains.
func NewLineToChainPtrWorker(p *Processor, numWorker int) *lineToChainPtrWorker {
	w := &lineToChainPtrWorker{
		now:   time.Now(),
		cache: cache.NewLruCache(LruCacheSize),
	}

	// Prepare stage.
	name := fmt.Sprintf("toChains_%02d", numWorker)
	// Create cached slices.
	chainCache := make([]*certChain, 1)
	channelCache := []int{0}
	w.Stage = pip.NewStage[line, *certChain](
		name,
		pip.WithProcessFunction(
			func(in line) ([]*certChain, []int, error) {
				var err error
				chainCache[0], err = w.parseLine(p, &in)
				return chainCache, channelCache, err
			},
		),
	)
	return w
}

// parseLine decodes one compact CSV row into a pointer-based certificate chain representation.
func (w *lineToChainPtrWorker) parseLine(p *Processor, line *line) (*certChain, error) {
	// First avoid even parsing already expired certs. As in the value-based worker, we only
	// inspect the compact expiration field extracted by the CSV stage.
	n, err := getExpiration(line.expirationField)
	if err != nil {
		return nil, err
	}
	if w.now.After(time.Unix(n, 0)) {
		// Skip this certificate.
		return nil, nil
	}

	// Decode the leaf certificate payload directly from the byte-oriented CSV representation.
	rawBytes, err := decodeBase64Field(line.certField)
	if err != nil {
		return nil, err
	}

	// Update statistics.
	p.Manager.Stats.ReadBytes.Add(int64(len(rawBytes)))
	p.Manager.Stats.ReadCerts.Add(1)
	p.Manager.Stats.UncachedCerts.Add(1)

	// Get the leaf certificate ID.
	certID := common.SHA256Hash32Bytes(rawBytes)
	if w.cache.Contains(&certID) {
		// The leaf was already seen by this worker, so skip duplicate work and output.
		return nil, nil
	}
	cert, err := ctx509.ParseCertificate(rawBytes)
	if err != nil {
		return nil, err
	}

	// Although we checked right at the beginning with getExpiration, now use the payload.
	if w.now.After(cert.NotAfter) {
		// Don't ingest already expired certificates.
		return nil, nil
	}

	// The chain is still represented as semicolon-delimited base64 payloads.
	chainFields := splitSemicolonField(line.chainField)
	chain := make([]*ctx509.Certificate, len(chainFields))
	chainIDs := make([]*common.SHA256Output, len(chainFields))
	for i, s := range chainFields {
		rawBytes, err = decodeBase64Field(s)
		if err != nil {
			return nil, fmt.Errorf("at line %d: %s\n%s",
				line.number, err, string(line.chainField))
		}
		// Update statistics.
		p.Manager.Stats.ReadBytes.Add(int64(len(rawBytes)))
		p.Manager.Stats.ReadCerts.Add(1)
		// Check if the parent certificate is in the cache.
		id := common.SHA256Hash32Bytes(rawBytes)
		if !w.cache.Contains(&id) {
			// Keep only the parent payloads that have not already been observed by this worker.
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return nil, fmt.Errorf("at line %d: %s\n%s",
					line.number, err, string(line.chainField))
			}
			w.cache.AddIDs(&id)
			p.Manager.Stats.UncachedCerts.Add(1)
		}
		chainIDs[i] = &id
	}

	return &certChain{
		Cert:          cert,
		CertID:        certID,
		ChainPayloads: chain,
		ChainIDs:      chainIDs,
	}, nil
}
