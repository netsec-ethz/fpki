package main

import (
	"sync"

	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	"github.com/netsec-ethz/fpki/pkg/util"
)

type ChainsToCertificatesPipeline struct {
	IncomingChan     chan updater.CertWithChainData // New files with certificates to be ingested.
	NextStageChan    *chan updater.Certificate      // Should be readied by the next stage.
	OnBundleFinished func()

	nextStage     *updater.Manager
	bundleMaxSize uint64 // The max amount of certs before we have a bundle.

	errChan chan error
}

func NewChainsToCertificatesPipeline(bundleSize uint64) *ChainsToCertificatesPipeline {
	return &ChainsToCertificatesPipeline{
		OnBundleFinished: func() {}, // Defaults to noop.
		bundleMaxSize:    bundleSize,
	}
}

func (p *ChainsToCertificatesPipeline) Resume() {
	p.nextStage.Resume()
	p.resume()
}

func (p *ChainsToCertificatesPipeline) Stop() {
	close(p.IncomingChan)
}

func (p *ChainsToCertificatesPipeline) Wait() error {
	// Wait needs to check if there were errors in this or the next stage.
	errors := make([]error, 2)
	wg := sync.WaitGroup{}
	wg.Add(len(errors))

	// This stage status.
	go func() {
		defer wg.Done()
		errors[0] = <-p.errChan
		if errors[0] != nil {
			// Error in this stage. Stop the next one.
		}
	}()

	// Next stage status.
	go func() {
		defer wg.Done()
		errors[1] = p.nextStage.Wait()

	}()
	wg.Wait()

	// In both cases we need to close the incoming channel of the next stage.
	p.nextStage.Stop()

	return util.ErrorsCoalesce(errors...)
}

func (p *ChainsToCertificatesPipeline) resume() {
	p.IncomingChan = make(chan updater.CertWithChainData)

	// Process the parsed content into Certificates and send them to the updater.
	// OnBundleFinished, called from callForEachBundle, would coalesce certs and update the SMT.
	go func() {
		var flyingCertCount uint64
		for data := range p.IncomingChan {
			certs := updater.CertificatesFromChains(&data)
			for _, c := range certs {
				*p.NextStageChan <- c
				flyingCertCount++
				// Check that if by adding this certificate we exceed the maximum amount of
				// "flying" certificates (not coalesced and whose SMT is not updated).
				// If so, we need to call the OnBundleFinished callback.
				if flyingCertCount == p.bundleMaxSize {
					// deleteme we should have errors for the call for each bundle.
					p.callForEachBundle(true)
					flyingCertCount = 0
				}
			}
		}

		resume := false
		if flyingCertCount > 0 {
			resume = true
		}

		p.callForEachBundle(resume)

		// There is no more processing to do, close the errors channel and allow the
		// error processor to finish.
		close(p.errChan)
	}()
}

// callForEachBundle waits until all certificates have been updated in the DB.
// If the parameter resume is true, it will prepare the certificate processor for more bundles.
func (p *ChainsToCertificatesPipeline) callForEachBundle(resumeNextStage bool) {
	// Stop the next stage.
	p.nextStage.Stop()

	// And wait for it to finish.
	p.nextStage.Wait()

	// Actual call per bundle.
	p.OnBundleFinished()

	// If we need to resume, do so.
	if resumeNextStage {
		p.nextStage.Resume()
	}
}
