package updater

import (
	"context"
	"time"

	"github.com/netsec-ethz/fpki/pkg/cache"
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
	bundleSize uint64,
	onBundleFunc func(),
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
	return pip.NewSource[Certificate](
		"incoming_certs",
		pip.WithMultiOutputChannels[pip.None, Certificate](2*workerCount),
		pip.WithSourceChannel(&m.IncomingCertChan, func(in Certificate) ([]int, error) {
			i := int(m.ShardFuncCert(&in.CertID))
			return []int{
				i,               // To batcher i
				i + workerCount, // To domain extractor i
			}, nil
		}),
	)
}

// createPipeline prepares the stages for processing certificates all the way until insertion in DB,
// as well as extraction of domains and their insertion in DB.
// W = number of workers.
// The stages are:
//
//	A: source, generates Certificate, 2*W outputs, to Bi and Ci
//	B1..W: batcher, transforms into certBatch, outputs to Ci
//	C1..W: domain extractor, transforms into DirtyDomain, outputs to E1..W but no crisscross.

//	D1..W: certificate to CSV, outputs to one Ei.
//	E1..W: cert CSV to DB, outputs to one Fi.
//	F1..W: cert CSV removal. Sink.

//	G1..W: domain batcher, transforms into domainBatch, outputs to one Hi
//	H1..W: domain inserter, inserts into DB. Sink.
//
// The indices are below:
// A: 0
// B: 1..W				cert batchers
// C: W+1..2W			domain extractors
// D: 2W+1..3W			csv creators
// E: 3W+1..4W			csv inserters
// F: 4W+1..5W			csv removers
// G: 5W+1..6W			domain batchers
// H: 6W+1..7W			domain csv creators
// I: 7W+1..8W			domain csv inserters
// J: 8W+1..9W			domain csv removers
//
//	A -┌-> B1 ---> D1 ---> E1 ---> F1
//	   |-> B2 ---> D2 ---> E2 ---> F2
//	  ...
//	   |-> Bw ---> Dw ---> Ew ---> Fw
//	   |
//	   |-> C1 -┬-> G1 ---> H1 ---> I1 ---> J1
//	   |-> C2 -|-> G2 ---> H2 ---> I2 ---> J2
//	  ...     .|.
//	   └-> Cw -┴-> Gw ---> Hw ---> Iw ---> Jw
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

	// Prepare the domain extractors. Stages C1..Cw
	domainCache := cache.NewLruCache(domainIdCacheSize)

	domainExtractors := make([]*domainExtractor, workerCount)
	domainExtractorStages := make([]pip.StageLike, workerCount)
	for i := range domainExtractors {
		domainExtractors[i] = newDomainExtractor(i, m, workerCount, domainCache)
		domainExtractorStages[i] = domainExtractors[i].Stage
	}

	// Prepare the certificate to CSV creators. Stages D1..Dw
	certCsvCreators := make([]*certBatchToCsv, workerCount)
	certCsvCreatorStages := make([]pip.StageLike, workerCount)
	for i := range certCsvCreators {
		certCsvCreators[i] = newCertBatchToCsv(i, m)
		certCsvCreatorStages[i] = certCsvCreators[i].Stage
	}

	// Prepare the cert csv to DB inserters. Stages E1..Ew.
	certCsvInserters := make([]*certCsvInserter, workerCount)
	certCsvInserterStages := make([]pip.StageLike, workerCount)
	for i := range certCsvInserters {
		certCsvInserters[i] = newCertCsvInserter(i, m)
		certCsvInserterStages[i] = certCsvInserters[i].Stage
	}

	// Prepare the cert csv removers. Sinks F1..Fw.
	certCsvRemovers := make([]*certCsvRemover, workerCount)
	certCsvRemoverStages := make([]pip.StageLike, workerCount)
	for i := range certCsvRemovers {
		certCsvRemovers[i] = newCertCsvRemover(i)
		certCsvRemoverStages[i] = certCsvRemovers[i].Sink
	}

	// Prepare the domain batchers.  Stages G1..Gw
	domainBatchers := make([]*domainBatcher, workerCount)
	domainBatcherStages := make([]pip.StageLike, workerCount)
	for i := range domainBatchers {
		domainBatchers[i] = newDomainBatcher(i, m, workerCount)
		domainBatcherStages[i] = domainBatchers[i].Stage
	}

	// Prepare the domain csv creators. Stages H1..Hw
	domainCsvsCreators := make([]*domainsToCsvs, workerCount)
	domainCsvsCreatorStages := make([]pip.StageLike, workerCount)
	for i := range domainCsvsCreators {
		domainCsvsCreators[i] = newDomainsToCsvs(i, m)
		domainCsvsCreatorStages[i] = domainCsvsCreators[i].Stage
	}

	// Prepare the domain csv inserters. Sinks I1...Iw
	domainCsvInserters := make([]*domainCsvsInserter, workerCount)
	domainCsvInserterStages := make([]pip.StageLike, workerCount)
	for i := range domainCsvInserters {
		domainCsvInserters[i] = newDomainCsvsInserter(i, m)
		domainCsvInserterStages[i] = domainCsvInserters[i].Stage
	}

	// Prepare the domain csv removers. Stages J1..Jw
	// Prepare the domain csv inserters. Sinks I1...Iw
	domainCsvsRemovers := make([]*domainCsvsRemover, workerCount)
	domainCsvsRemoverStages := make([]pip.StageLike, workerCount)
	for i := range domainCsvsRemovers {
		domainCsvsRemovers[i] = newDomainCsvsRemover(i)
		domainCsvsRemoverStages[i] = domainCsvsRemovers[i].Sink
	}

	// Collect all stages.
	stages := make([]pip.StageLike, 1, 1+2*workerCount)
	stages[0] = source                                // A
	stages = append(stages, certBatcherStages...)     // B
	stages = append(stages, domainExtractorStages...) // C

	stages = append(stages, certCsvCreatorStages...)  // D
	stages = append(stages, certCsvInserterStages...) // E
	stages = append(stages, certCsvRemoverStages...)  // F

	stages = append(stages, domainBatcherStages...)     // G
	stages = append(stages, domainCsvsCreatorStages...) // H
	stages = append(stages, domainCsvInserterStages...) // I
	stages = append(stages, domainCsvsRemoverStages...) // J

	// Create pipeline.
	var err error
	m.Pipeline, err = pip.NewPipeline(
		func(p *pip.Pipeline) {

			// Link source with cert batchers. A -> B1..w
			for i, batcher := range certBatchers {
				pip.LinkStagesAt(
					source.Stage, i,
					batcher.Stage, 0,
				)
			}

			// Link source with domain extractors. A -> C1..w
			for i, extractor := range domainExtractors {
				pip.LinkStagesAt(
					source.Stage, i+workerCount,
					extractor.Stage, 0,
				)
			}

			// Link cert batchers to cert CSV creators. Bi -> Di
			for i, batcher := range certBatchers {
				pip.LinkStagesFanOut(
					batcher.Stage,
					certCsvCreators[i].Stage,
				)
			}

			// Link cert CSV creators to CSV inserters. Di -> Ei
			for i, creator := range certCsvCreators {
				pip.LinkStagesFanOut(
					creator.Stage,
					certCsvInserters[i].Stage,
				)
			}

			// Link cert CSV inserter to CSV remover. Ei -> Fi
			for i, inserter := range certCsvInserters {
				pip.LinkStagesFanOut(
					inserter.Stage,
					certCsvRemovers[i].Stage,
				)
			}

			// Link domain extractors to domain batchers. Ci -> G1..Gw, no crisscross.
			for i, extractor := range domainExtractors {
				for j, batcher := range domainBatchers {
					pip.LinkStagesAt(
						extractor.Stage, j, // e.g. extractor0_out[j] to batcherJ_in[0]
						batcher.Stage, i,
					)
				}
			}

			// Link domain batchers with domain csv creators.
			for i, batcher := range domainBatchers {
				pip.LinkStagesFanOut(
					batcher.Stage,
					domainCsvsCreators[i].Stage,
				)
			}

			// Link domain csv creators with domain csv inserters.
			for i, batcher := range domainCsvsCreators {
				pip.LinkStagesFanOut(
					batcher.Stage,
					domainCsvInserters[i].Stage,
				)
			}

			// Link domain csv inserters with domain csvs removers.
			for i, batcher := range domainCsvInserters {
				pip.LinkStagesFanOut(
					batcher.Stage,
					domainCsvsRemovers[i].Stage,
				)
			}
		},
		pip.WithStages(stages...),
	)

	return err
}
