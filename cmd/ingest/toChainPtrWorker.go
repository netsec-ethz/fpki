package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
)

type lineToChainPtrWorker struct {
	*pip.Stage[line, *certChain]

	now      time.Time
	presence cache.Cache // IDs of certificates already seen
}

func NewLineToChainPtrWorker(p *Processor, numWorker int) *lineToChainPtrWorker {
	w := &lineToChainPtrWorker{
		now:      time.Now(),
		presence: cache.NewPresenceCache(LruCacheSize),
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

func (w *lineToChainPtrWorker) parseLine(p *Processor, line *line) (*certChain, error) {
	// First avoid even parsing already expired certs.
	n, err := getExpiration(line.fields)
	if err != nil {
		return nil, err
	}
	if w.now.After(time.Unix(n, 0)) {
		// Skip this certificate.
		return nil, nil
	}

	// From this point on, we need to parse the certificate.
	rawBytes, err := base64.StdEncoding.DecodeString(line.fields[CertificateColumn])
	if err != nil {
		return nil, err
	}

	// Update statistics.
	p.stats.ReadBytes.Add(int64(len(rawBytes)))
	p.stats.ReadCerts.Add(1)
	p.stats.UncachedCerts.Add(1)

	// Get the leaf certificate ID.
	certID := common.SHA256Hash32Bytes(rawBytes)
	if w.presence.Contains(&certID) {
		// For some reason this leaf certificate has been ingested already. Skip.
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

	// The certificate chain is a list of base64 strings separated by semicolon (;).
	strs := strings.Split(line.fields[CertChainColumn], ";")
	chain := make([]*ctx509.Certificate, len(strs))
	chainIDs := make([]*common.SHA256Output, len(strs))
	for i, s := range strs {
		rawBytes, err = base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("at line %d: %s\n%s",
				line.number, err, line.fields[CertChainColumn])
		}
		// Update statistics.
		p.stats.ReadBytes.Add(int64(len(rawBytes)))
		p.stats.ReadCerts.Add(1)
		// Check if the parent certificate is in the cache.
		id := common.SHA256Hash32Bytes(rawBytes)
		if !w.presence.Contains(&id) {
			// Not seen before, push it to the DB.
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return nil, fmt.Errorf("at line %d: %s\n%s",
					line.number, err, line.fields[CertChainColumn])
			}
			w.presence.AddIDs(&id)
			p.stats.UncachedCerts.Add(1)
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
