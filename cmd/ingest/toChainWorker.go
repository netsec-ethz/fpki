package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
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

// String returns a compact debug label for a parsed certificate chain.
func (c certChain) String() string {
	return updater.CertWithChainData(c).String()
}

type lineToChainWorker struct {
	*pip.Stage[line, certChain]

	now   time.Time
	cache cache.Cache // IDs of certificates already seen
}

// NewLineToChainWorker creates a stage that turns compact CSV rows into parsed certificate chains.
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

// parseLine decodes one compact CSV row into a leaf certificate plus its parent chain metadata.
func (w *lineToChainWorker) parseLine(p *Processor, line *line) (*certChain, error) {
	// First avoid even parsing already expired certs. The splitter already isolated the last
	// column for us, so we can parse the timestamp without materializing the whole row.
	n, err := getExpiration(line.expirationField)
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

	// From this point on, we need the actual leaf payload. Decode directly from the compact
	// byte field produced by the fast/slow CSV parser.
	rawBytes, err := decodeBase64Field(line.certField)
	if err != nil {
		return nil, err
	}

	// Update bytes read.
	p.Manager.Stats.ReadBytes.Add(int64(len(rawBytes)))

	// Get the leaf certificate ID.
	certID := common.SHA256Hash32Bytes(rawBytes)
	if w.cache.Contains(&certID) {
		// The leaf was already seen by this worker, so avoid reparsing and reinserting it.
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

	// The certificate chain field is still semicolon-delimited. Split it lazily without
	// converting the whole field to []string first.
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
			// Only parse and keep parent payloads that still need to be unfolded into DB rows.
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

// getExpiration returns the expiration time in seconds. It is stored already in seconds on the
// last column of the CSV entry, usually index 7.
func getExpiration(field []byte) (int64, error) {
	// Expiration values are stored as "<unix-seconds>.<fraction>" in the last column.
	dot := bytes.IndexByte(field, '.')
	if dot <= 0 || dot == len(field)-1 {
		return 0, fmt.Errorf("unrecognized timestamp in the last column: %s", string(field))
	}
	exp, err := strconv.ParseInt(string(field[:dot]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing the expiration time \"%s\" got: %w",
			string(field), err)
	}
	return exp, nil
}

// splitSemicolonField returns subslices for each semicolon-delimited chain payload.
func splitSemicolonField(field []byte) [][]byte {
	// Keep subslices pointing into the original row buffer to avoid allocating per chain element.
	count := 1
	for _, b := range field {
		if b == ';' {
			count++
		}
	}
	parts := make([][]byte, 0, count)
	start := 0
	for i := 0; i <= len(field); i++ {
		if i < len(field) && field[i] != ';' {
			continue
		}
		parts = append(parts, field[start:i])
		start = i + 1
	}
	return parts
}

// decodeBase64Field decodes one base64-encoded CSV field into its raw bytes.
func decodeBase64Field(field []byte) ([]byte, error) {
	// Allocate exactly once for the decoded payload and let the base64 package fill it in place.
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(field)))
	n, err := base64.StdEncoding.Decode(dst, field)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
