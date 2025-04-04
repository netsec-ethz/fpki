package main

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	ctx509 "github.com/google/certificate-transparency-go/x509"

	"github.com/netsec-ethz/fpki/pkg/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

type certChain updater.CertWithChainData

func (c certChain) String() string {
	return updater.CertWithChainData(c).String()
}

type lineToChainWorker struct {
	*pip.Stage[line, certChain]

	now   time.Time
	cache cache.Cache // IDs of certificates already seen
}

func NewLineToChainWorker(p *Processor, numWorker int) *lineToChainWorker {
	w := &lineToChainWorker{
		now:   time.Now(),
		cache: cache.NewLruCache(LruCacheSize),
	}

	// Prepare stage.
	name := fmt.Sprintf("toChains_%02d", numWorker)
	// Create cached slices.
	chainCache := make([]certChain, 1)
	channelCache := []int{0}
	w.Stage = pip.NewStage[line, certChain](
		name,
		pip.WithProcessFunction(
			func(in line) ([]certChain, []int, error) {
				chain, err := w.parseLine(p, &in)
				if chain == nil {
					// Skipped line, return nothing.
					return nil, nil, err
				}
				chainCache[0] = *chain
				return chainCache, channelCache, err
			},
		),
	)
	return w
}

func (w *lineToChainWorker) parseLine(p *Processor, line *line) (*certChain, error) {
	// First avoid even parsing already expired certs.
	n, err := getExpiration(line.fields)
	if err != nil {
		return nil, err
	}

	// Regardless of whether we skip it or not, we processed one more cert.
	p.Manager.Stats.ReadCerts.Add(1)

	if w.now.After(time.Unix(n, 0)) {
		// Skip this certificate.
		p.Manager.Stats.ExpiredCerts.Add(1)
		return nil, nil
	}

	// From this point on, we need to parse the certificate.
	rawBytes, err := base64.StdEncoding.DecodeString(line.fields[CertificateColumn])
	if err != nil {
		return nil, err
	}

	// Update bytes read.
	p.Manager.Stats.ReadBytes.Add(int64(len(rawBytes)))

	// Get the leaf certificate ID.
	certID := common.SHA256Hash32Bytes(rawBytes)
	if w.cache.Contains(&certID) {
		// For some reason this leaf certificate has been ingested already. Skip.
		return nil, nil
	}

	p.Manager.Stats.UncachedCerts.Add(1)

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
		p.Manager.Stats.ReadBytes.Add(int64(len(rawBytes)))
		p.Manager.Stats.ReadCerts.Add(1)
		// Check if the parent certificate is in the cache.
		id := common.SHA256Hash32Bytes(rawBytes)
		if !w.cache.Contains(&id) {
			// Not seen before, push it to the DB.
			chain[i], err = ctx509.ParseCertificate(rawBytes)
			if err != nil {
				return nil, fmt.Errorf("at line %d: %s\n%s",
					line.number, err, line.fields[CertChainColumn])
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

// getExpiration returns the expiration time in seconds. It is stored already in seconds on the
// last column of the CSV entry, usually index 7.
func getExpiration(fields []string) (int64, error) {
	// Because some entries in the CSVs are malformed by not escaping their SAN field, we cannot
	// reliably use a column index, but the last column of the entry.
	expirationColumn := len(fields) - 1

	s := strings.Split(fields[expirationColumn], ".")
	if len(s) != 2 {
		return 0, fmt.Errorf("unrecognized timestamp in the last column: %s", fields[expirationColumn])
	}
	exp, err := strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing the expiration time \"%s\" got: %w",
			fields[expirationColumn], err)
	}
	return exp, nil
}
