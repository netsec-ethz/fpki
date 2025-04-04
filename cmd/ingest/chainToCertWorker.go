package main

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// chainToCertWorker processes a chain into a slice of certificates.
type chainToCertWorker struct {
	*pip.Stage[certChain, updater.Certificate]

	channelsCache []int // reuse storage
}

func NewChainToCertWorker(numWorker int, p *Processor) *chainToCertWorker {
	w := &chainToCertWorker{}
	name := fmt.Sprintf("toCerts_%02d", numWorker)
	w.Stage = pip.NewStage[certChain, updater.Certificate](
		name,
		pip.WithProcessFunction(func(in certChain) ([]updater.Certificate, []int, error) {
			// Obtain the certificates from the chain.
			certs := updater.CertificatesFromChains((*updater.CertWithChainData)(&in))
			// TODO: use a []Certificate storage cache here to avoid allocating.

			// Recreate channel indices, all to zero.
			util.ResizeSlice(&w.channelsCache, len(certs), 0)

			// Increment the count of certs.
			p.certsBeforeBundle.Add(uint64(len(certs)))

			return certs, w.channelsCache, nil
		}),
	)
	return w
}
