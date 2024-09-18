package main

import (
	"fmt"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// chainPtrToCertPtrsWorker processes a chain into a slice of certificates.
type chainPtrToCertPtrsWorker struct {
	*pip.Stage[*certChain, *updater.Certificate]

	channelsCache []int // reuse storage
}

func NewChainPtrToCertPtrWorker(numWorker int) *chainPtrToCertPtrsWorker {
	w := &chainPtrToCertPtrsWorker{}
	name := fmt.Sprintf("toCerts_%02d", numWorker)
	w.Stage = pip.NewStage[*certChain, *updater.Certificate](
		name,
		pip.WithProcessFunction(func(in *certChain) ([]*updater.Certificate, []int, error) {
			// Obtain the certificates from the chain.
			certs := updater.CertificatePtrsFromChains((*updater.CertWithChainData)(in))
			// TODO: use a []Certificate storage cache here to avoid allocating.

			// Create channel indices, all to zero.
			util.ResizeSlice(&w.channelsCache, len(certs), 0)

			return certs, w.channelsCache, nil
		}),
		pip.WithSequentialOutputs[*certChain, *updater.Certificate](),
	)
	return w
}
