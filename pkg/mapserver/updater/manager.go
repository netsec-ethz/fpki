package updater

import (
	"context"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

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

	IncomingCertChan chan Certificate // Certificates arrive from this channel.
	Pipeline         *pip.Pipeline
}

// NewManager creates a new manager and its workers.
// The context ctx is used thru the lifetime of the workers, to perform DB operations, etc.
func NewManager(
	ctx context.Context,
	workerCount int,
	conn db.Conn,
	multiInsertSize int,
	statsUpdateFreq time.Duration,
	statsUpdateFunc func(*Stats),
) *Manager {
	// Compute how many bits we need to cover N partitions (i.e. ceil(log2(N-1)),
	// doable by computing the bit length of N-1 even if not a power of 2.
	nBits := int(util.Log2(uint(workerCount - 1)))

	selectPartition := func(id *common.SHA256Output) uint {
		return mysql.PartitionByIdMSB(id, nBits)
	}

	// Create the Manager structure.
	m := &Manager{
		MultiInsertSize: multiInsertSize,
		Stats:           NewStatistics(statsUpdateFreq, statsUpdateFunc),
		ShardFuncCert:   selectPartition,
		ShardFuncDomain: selectPartition,
	}

	// Prepare the domain processing stages. Sinks.
	domainWorkers := make([]*DomainWorker, workerCount)
	// Pure sink objects:
	domainStages := make([]pip.StageLike, workerCount)
	for i := range domainWorkers {
		domainWorkers[i] = NewDomainWorker(ctx, i, m, conn, workerCount)
		domainStages[i] = &domainWorkers[i].Sink
	}

	// Prepare the certificate processing stages.
	certWorkers := make([]*CertWorker, workerCount)
	// Stage 1-to-1: cert to DB and output domains.
	certStages := make([]pip.StageLike, workerCount)
	for i := range certWorkers {
		certWorkers[i] = NewCertWorker(ctx, i, m, conn, workerCount)
		certStages[i] = &certWorkers[i].Stage
	}

	// Get the Certificate from the channel and pass it along.
	source := pip.NewSource(
		"source",
		pip.WithGeneratorFunction(func() (Certificate, int, error) {
			for cert := range m.IncomingCertChan {
				outChIndex := m.ShardFuncCert(&cert.CertID)
				return cert, int(outChIndex), nil
			}
			return Certificate{}, 0, pip.NoMoreData
		}),
		pip.WithMultiOutputChannels[pip.None, Certificate](workerCount),
	)

	// Collect all stages.
	stages := make([]pip.StageLike, 1, 1+2*workerCount)
	stages[0] = source
	stages = append(stages, certStages...)
	stages = append(stages, domainStages...)

	// Create pipeline.
	m.Pipeline = pip.NewPipeline(
		func(p *pip.Pipeline) {
			// Link source with cert workers.
			for i := 0; i < workerCount; i++ {
				certWorker := p.Stages[i+1].(*pip.Stage[Certificate, DirtyDomain])

				pip.LinkStagesAt(
					pip.SourceAsStage(source), i,
					certWorker, 0,
				)
			}
			// Link cert workers with domain workers.
			// Each cert worker has N out channels. Link each one to one domain worker,
			// using the domain worker's ith input channel.
			for i := 0; i < workerCount; i++ {
				certWorker := p.Stages[i+1].(*pip.Stage[Certificate, DirtyDomain])
				for j := 0; j < workerCount; j++ {
					domainWorker := p.Stages[1+workerCount+j].(*pip.Sink[DirtyDomain])
					pip.LinkStagesAt(
						certWorker, j,
						pip.SinkAsStage(domainWorker), i,
					)
				}
			}

		},
		pip.WithStages(stages...))

	return m
}

func (m *Manager) Resume() {
	m.IncomingCertChan = make(chan Certificate)
	m.Pipeline.Resume()
}
func (m *Manager) Stop() {
	// Stop the source.
	close(m.IncomingCertChan)
}

func (m *Manager) Wait() error {
	return m.Pipeline.Wait()
}
