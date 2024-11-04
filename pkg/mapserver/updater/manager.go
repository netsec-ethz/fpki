package updater

import (
	"context"
	"time"

	"github.com/netsec-ethz/fpki/cmd/ingest/cache"
	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

const domainIdCacheSize = 10000

// Manager contains a processing pipeline that takes certificates and stores them concurrently
// using several workers (but the same one for the same certificate).
// It also extracts the domain objects of the certificates and sends them to the DB the same way.
// The requirement of using the same worker for a given certificate or domain prevents deadlocks
// in the DBE.
type Manager struct {
	Conn            db.Conn                         // DB
	MultiInsertSize int                             // amount of entries before calling the DB
	Stats           *Stats                          // Statistics about the update
	ShardFuncCert   func(*common.SHA256Output) uint // select cert worker index from ID
	ShardFuncDomain func(*common.SHA256Output) uint // select the domain worker from domain ID

	IncomingCertChan    chan Certificate  // Certificates arrive from this channel.
	IncomingCertPtrChan chan *Certificate // Only one of the incoming channels is enabled.
	Pipeline            *pip.Pipeline
}

// NewManager creates a new manager and its workers.
// The context ctx is used thru the lifetime of the workers, to perform DB operations, etc.
// Currently to use pointers to certificates instead of certificates, a code change is needed.
// It requires using the IncomingCertPtrChan instead of the other one, and calls to the
// *Ptr* functions instead of the current ones, e.g. NewCertPtrWorker, createCertificateSource,...
func NewManager(
	workerCount int,
	conn db.Conn,
	multiInsertSize int,
	statsUpdateFreq time.Duration,
	statsUpdateFunc func(*Stats),
) (*Manager, error) {
	// Compute how many bits we need to cover N partitions (i.e. log2(N).
	nBits := int(util.Log2(uint(workerCount)))

	selectPartition := func(id *common.SHA256Output) uint {
		return mysql.PartitionByIdMSB(id, nBits)
	}

	// Create the Manager structure.
	m := &Manager{
		Conn:             conn,
		MultiInsertSize:  multiInsertSize,
		Stats:            NewStatistics(statsUpdateFreq, statsUpdateFunc),
		ShardFuncCert:    selectPartition,
		ShardFuncDomain:  selectPartition,
		IncomingCertChan: make(chan Certificate),
		// IncomingCertPtrChan: make(chan *Certificate),
	}

	// Create the pipeline and return the manager with the pipeline, and the error.
	return m, m.createPipeline(workerCount)
}

func (m *Manager) Resume(ctx context.Context) {
	// Create a new source incoming channel.
	m.IncomingCertChan = make(chan Certificate)

	// Resume pipeline.
	m.Pipeline.Resume(ctx)
}
func (m *Manager) Stop() {
	// Stop the source.
	close(m.IncomingCertChan)
}

func (m *Manager) Wait(ctx context.Context) error {
	return m.Pipeline.Wait(ctx)
}

func (m *Manager) createCertificateSource(workerCount int) *pip.Source[Certificate] {
	outChannels := make([]int, 2)
	return pip.NewSource[Certificate](
		"incoming_certs",
		pip.WithMultiOutputChannels[pip.None, Certificate](2*workerCount),
		pip.WithSourceChannel(&m.IncomingCertChan, func(in Certificate) ([]int, error) {
			i := int(m.ShardFuncCert(&in.CertID))
			outChannels[0] = i               // To batcher i
			outChannels[1] = i + workerCount // To domain extractor i
			return outChannels, nil
		}),
	)
}

// createPipeline prepares the stages for processing certificates all the way until insertion in DB,
// as well as extraction of domains and their insertion in DB.
// W = number of workers.
// The stages are:
//
//	A: source, generates Certificate, 2*W outputs, to Bi and Di
//	B1..W: batcher, transforms into certBatch, outputs to Ci
//	C1..W: certificate inserter. Sink.
//	D1..W: domain extractor, transforms into DirtyDomain, outputs to E1..W
//	E1..W: domain batcher, transforms into domainBatch, outputs to Fi
//	F1..W: domain worker, inserts into DB. Sink.
//
// The indices are below:
// A: 0
// B: 1..W
// C: W+1..2W
// D: 2W+1..3W
// E: 3W+1..4W
// F: 4W+1..5W
//
//	A -┌-> B1 ---> C1
//	   |-> B2 ---> C2
//	  ...
//	   |-> Bw ---> Cw
//	   |
//	   |-> D1 -┬-> E1 ---> F1
//	   |-> D2 -|-> E2 ---> F2
//	  ...     .|.
//	   └-> Dw -┴-> Ew ---> Fw
//	.
func (m *Manager) createPipeline(workerCount int) error {
	// Get the Certificate from the channel and pass it along.
	source := m.createCertificateSource(workerCount)

	// Prepare the certificate batchers. Stages B1..Bw
	certBatchers := make([]*certBatcher, workerCount)
	certBatcherStages := make([]pip.StageLike, workerCount)
	for i := range certBatchers {
		certBatchers[i] = newCertBatcher(i, m)
		certBatcherStages[i] = certBatchers[i].Stage
	}

	// Prepare the certificate inserters.  Stages C1..Cw
	certInserters := make([]*certInserter, workerCount)
	certInserterStages := make([]pip.StageLike, workerCount)
	for i := range certInserters {
		certInserters[i] = newCertInserter(i, m)
		certInserterStages[i] = certInserters[i].Sink
	}

	// Prepare the domain extractors.  Stages D1..Dw
	domainCache := cache.NewPresenceCache(domainIdCacheSize)
	domainExtractors := make([]*domainExtractor, workerCount)
	domainExtractorStages := make([]pip.StageLike, workerCount)
	for i := range domainExtractors {
		domainExtractors[i] = newDomainExtractor(i, m, workerCount, domainCache)
		domainExtractorStages[i] = domainExtractors[i].Stage
	}

	// Prepare the domain batchers.  Stages E1..Ew
	domainBatchers := make([]*domainBatcher, workerCount)
	domainBatcherStages := make([]pip.StageLike, workerCount)
	for i := range domainBatchers {
		domainBatchers[i] = newDomainBatcher(i, m, workerCount)
		domainBatcherStages[i] = domainBatchers[i].Stage
	}

	// Prepare the domain inserters. Sinks F1...Fw
	domainInserters := make([]*domainInserter, workerCount)
	domainInserterStages := make([]pip.StageLike, workerCount)
	for i := range domainInserters {
		domainInserters[i] = newDomainInserter(i, m)
		domainInserterStages[i] = domainInserters[i].Sink
	}

	// Collect all stages.
	stages := make([]pip.StageLike, 1, 1+2*workerCount)
	stages[0] = source                                // A
	stages = append(stages, certBatcherStages...)     // B
	stages = append(stages, certInserterStages...)    // C
	stages = append(stages, domainExtractorStages...) // D
	stages = append(stages, domainBatcherStages...)   // E
	stages = append(stages, domainInserterStages...)  // F

	// Create pipeline.
	var err error
	m.Pipeline, err = pip.NewPipeline(
		func(p *pip.Pipeline) {
			// Offsets for all stage types:
			offsetCertBatchers := 1                                      // B
			offsetCertInserters := offsetCertBatchers + workerCount      // C
			offsetDomainExtractors := offsetCertInserters + workerCount  // D
			offsetDomainBatchers := offsetDomainExtractors + workerCount // E
			offsetDomainInserters := offsetDomainBatchers + workerCount  // F

			// Link source with cert batchers. A -> B1..w
			for i := 0; i < workerCount; i++ {
				certBatcher := p.Stages[offsetCertBatchers+i].(*pip.Stage[Certificate, certBatch])
				pip.LinkStagesAt(
					pip.SourceAsStage(source), i,
					certBatcher, 0,
				)
			}
			// Link source with domain extractors. A -> D1..w
			for i := 0; i < workerCount; i++ {
				domainExtractor := p.Stages[offsetDomainExtractors+i].(*pip.Stage[Certificate, DirtyDomain])
				pip.LinkStagesAt(
					pip.SourceAsStage(source), i+workerCount,
					domainExtractor, 0,
				)
			}

			// Link cert batchers to cert inserters. Bi -> Ci
			for i := 0; i < workerCount; i++ {
				certBatcher := p.Stages[offsetCertBatchers+i].(*pip.Stage[Certificate, certBatch])
				certInserter := p.Stages[offsetCertInserters+i].(*pip.Sink[certBatch])
				pip.LinkStagesFanOut(certBatcher, pip.SinkAsStage(certInserter))
			}

			// Link domain extractors to domain batchers. Di -> E1..Ew
			for i := 0; i < workerCount; i++ {
				domainExtractor := p.Stages[offsetDomainExtractors+i].(*pip.Stage[Certificate, DirtyDomain])
				for j := 0; j < workerCount; j++ {
					domainBatcher := p.Stages[offsetDomainBatchers+j].(*pip.Stage[DirtyDomain, domainBatch])
					pip.LinkStagesAt(
						domainExtractor, j, // Each D has w out channels.
						domainBatcher, i,
					)
				}
			}

			// Link domain batchers with domain inserters.
			for i := 0; i < workerCount; i++ {
				domainBatcher := p.Stages[offsetDomainBatchers+i].(*pip.Stage[DirtyDomain, domainBatch])
				domainInserter := p.Stages[offsetDomainInserters+i].(*pip.Sink[domainBatch])
				pip.LinkStagesFanOut(domainBatcher, pip.SinkAsStage(domainInserter))
			}
		},
		pip.WithStages(stages...),
	)

	return err
}
