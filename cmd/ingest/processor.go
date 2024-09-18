package main

import (
	"context"
	"math"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// Processor is the processor that takes file names and process them into certificates.
// It makes use of a pipeline that keeps the order of the certificates. Depicted below:
/*
 CsvFile ---┌-> line1 -> Chain1 ┌-> Cert1.1
			|                   |-> Cert1.2
			|                  ...
			|-> line2 -> Chain2 ┌-> Cert2.1
			|                   |-> Cert2.2
			|                  ...
		   ...
*/
type Processor struct {
	CsvFiles         []util.CsvFile
	NumWorkers       int
	NumDBWriters     int
	BundleSize       uint64
	OnBundleFinished func()

	stats                 *updater.Stats //pointer to the actual stats living in Manager
	certSinkHasNoMoreData bool           // True when the cert sink receives onNoMoreData

	Pipeline *pip.Pipeline
}

func NewProcessor(
	ctx context.Context,
	conn db.Conn,
	multiInsertSize int,
	statsUpdatePeriod time.Duration,
	statsUpdateFun func(*updater.Stats),
	options ...processorOptions,
) (*Processor, error) {
	// Create the processor that will hold all the information and the pipeline.
	p := &Processor{
		NumWorkers:       1,              // Default to just 1 worker.
		NumDBWriters:     1,              // Default to 1 db writer.
		BundleSize:       math.MaxUint64, // Default to "no limit",
		OnBundleFinished: func() {},      // Default to noop.

		certSinkHasNoMoreData: false,
	}
	for _, opt := range options {
		opt(p)
	}

	// Create the pipFiles from files to Certificates.
	pipFiles, err := p.createFilesToCertsPipeline()
	if err != nil {
		return nil, err
	}

	// Create the DB manager.
	manager, err :=
		updater.NewManager(ctx, p.NumDBWriters, conn, multiInsertSize, statsUpdatePeriod, statsUpdateFun)
	if err != nil {
		return nil, err
	}
	// Link to the stats.
	p.stats = manager.Stats

	// Join the two pipelines.
	pipeline, err := pip.JoinTwoPipelines[updater.Certificate](pipFiles, manager.Pipeline)
	if err != nil {
		return nil, err
	}

	// Set the joint pipeline as the pipeline and return.
	p.Pipeline = pipeline
	return p, nil
}

type processorOptions func(*Processor)

func WithNumWorkers(numWorkers int) processorOptions {
	return func(p *Processor) {
		p.NumWorkers = numWorkers
	}
}

func WithNumDBWriters(numDBWriters int) processorOptions {
	return func(p *Processor) {
		p.NumDBWriters = numDBWriters
	}
}

func WithBundleSize(bundleSize uint64) processorOptions {
	return func(p *Processor) {
		if bundleSize == 0 {
			bundleSize = math.MaxUint64
		}
		p.BundleSize = bundleSize
	}
}

func WithOnBundleFinished(fcn func()) processorOptions {
	return func(p *Processor) {
		p.OnBundleFinished = fcn
	}
}

func (p *Processor) Resume() {
	p.Pipeline.Resume()
}

func (p *Processor) Wait() error {
	return p.Pipeline.Wait()
}

// AddGzFiles adds a CSV .gz file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddGzFiles(fileNames []string) {
	p.stats.TotalFiles.Add(int64(len(fileNames)))

	for _, filename := range fileNames {
		p.CsvFiles = append(p.CsvFiles, (&util.GzFile{}).WithFile(filename))
	}
}

// AddCsvFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddCsvFiles(fileNames []string) {
	p.stats.TotalFiles.Add(int64(len(fileNames)))

	for _, filename := range fileNames {
		p.CsvFiles = append(p.CsvFiles, (&util.UncompressedFile{}).WithFile(filename))
	}
}

// createFilesToCertsPipeline creates a pipeline that processes CSV and GZ files into Certificates.
// It can be joined together with a Manager to push the Certificates into the DB.
// The created pipeline looks like this:
//
//	A: source, generates CsvFile
//	B: transforms into []line, multiple outputs.
//	C1..W: transforms into Chain.
//	D1..W: transforms into []Certificate.
//	E: sink, multiple inputs, []Certificate.
//
// The indices are below:
// A: 0
// B: 1
// C: 2..2+W
// D: 2+W..2+2W
// E: 3+2W
//
//	A -> B -┌-> C1 ---> D1 -┬-> E
//	        |-> C2 ---> D2 -|
//		   ...             ...
//		    └-> Cw ---> Dw -┘
func (p *Processor) createFilesToCertsPipeline() (*pip.Pipeline, error) {
	// Prepare source. It opens CSV files based on the filenames stored in the processor.
	csvFileIndex := 0
	source := pip.NewSource[util.CsvFile](
		"files",
		pip.WithSourceFunction(
			func() ([]util.CsvFile, []int, error) {
				defer func() { csvFileIndex++ }()
				if csvFileIndex < len(p.CsvFiles) {
					return p.CsvFiles[csvFileIndex : csvFileIndex+1], []int{0}, nil
				}
				return nil, nil, pip.NoMoreData
			},
		),
		pip.WithSequentialOutputs[pip.None, util.CsvFile](),
	)

	// Create CSV split worker.
	splitter := NewCsvSplitWorker(p)

	// Create numParsers toChain workers. Parses lines into chains.
	lineToChainWorkers := make([]*lineToChainWorker, p.NumWorkers)
	for i := range lineToChainWorkers {
		lineToChainWorkers[i] = NewLineToChainWorker(p, i)
	}

	// Create chain to certificates worker.
	chainToCertWorkers := make([]*chainToCertWorker, p.NumWorkers)
	for i := range chainToCertWorkers {
		chainToCertWorkers[i] = NewChainToCertWorker(i)
	}

	// Create sink for certificate pointers.
	sink := p.createCertificateSink()

	stages := []pip.StageLike{source, splitter.Stage}
	for _, w := range lineToChainWorkers {
		stages = append(stages, w.Stage)
	}
	for _, w := range chainToCertWorkers {
		stages = append(stages, w.Stage)
	}
	stages = append(stages, sink)

	pipeline, err := pip.NewPipeline(
		func(pipeline *pip.Pipeline) {
			/* Link function.
				A: source, generates CsvFile
				B: transforms into []line, multiple outputs.
				C1..W: transforms into Chain.
				D1..W: transforms into []Certificate.
				E: sink, multiple inputs.
			The indices are below:
			A: 0
			B: 1
			C: 2..2+W
			D: 2+W..2+2W
			E: 3+2W

			A -> B -┌-> C1 ---> D1 -┬-> E
			        |-> C2 ---> D2 -|
				   ...             ...
				    └-> Cw ---> Dw -┘
			*/
			a := pip.SourceStage[util.CsvFile](pipeline)
			b := pip.StageAtIndex[util.CsvFile, line](pipeline, 1)
			c := make([]*pip.Stage[line, certChain], p.NumWorkers)
			for i := range c {
				c[i] = pip.StageAtIndex[line, certChain](pipeline, i+2)
			}
			d := make([]*pip.Stage[certChain, updater.Certificate], p.NumWorkers)
			for i := range c {
				d[i] = pip.StageAtIndex[certChain, updater.Certificate](pipeline, i+2+p.NumWorkers)
			}
			e := pip.SinkStage[updater.Certificate](pipeline)

			pip.LinkStagesFanOut(a, b) //           A->B
			for i := range c {
				pip.LinkStagesAt(b, i, c[i], 0)  // B->Ci
				pip.LinkStagesFanOut(c[i], d[i]) // Ci->Di
				pip.LinkStagesAt(d[i], 0, e, i)  // Di->E
			}
			// done.
		},
		pip.WithStages(stages...),
		pip.WithAutoResumeAtStage(
			len(stages)-1,
			func() bool {
				// Call for each bundle. This call is ensured to be performed after all the next
				// stages have finished.
				p.OnBundleFinished()

				// resume if not finished.
				return !p.certSinkHasNoMoreData
				// return !noMoreData
			},
			func(p *pip.Pipeline) {
				// Relink function, no affected stages.
			},
		),
	)

	return pipeline, err
}

func (p *Processor) createCertificateSink() *pip.Sink[updater.Certificate] {
	var certProcessedCount uint64 = 0 // For the sink to call on bundle.
	return pip.NewSink[updater.Certificate](
		"certSink",
		pip.WithMultiInputChannels[updater.Certificate, pip.None](p.NumWorkers),
		pip.WithOnNoMoreData[updater.Certificate, pip.None](func() ([]pip.None, []int, error) {
			p.certSinkHasNoMoreData = true // Flag that the pipeline has no more data to process.
			return nil, nil, nil
		}),
		pip.WithSinkFunction(func(in updater.Certificate) error {
			var err error
			certProcessedCount++
			p.stats.WrittenCerts.Add(1)
			p.stats.WrittenBytes.Add(int64(len(in.Cert.Raw)))

			if certProcessedCount >= p.BundleSize {
				// Reset counters.
				certProcessedCount = 0
				// Request the next stages to stop.
				err = pip.NoMoreData
			}
			return err
		}),
	)
}

func (p *Processor) createCertificatePtrSink() *pip.Sink[*updater.Certificate] {
	var certProcessedCount uint64 = 0 // For the sink to call on bundle.
	return pip.NewSink[*updater.Certificate](
		"certSink",
		pip.WithMultiInputChannels[*updater.Certificate, pip.None](p.NumWorkers),
		// pip.WithSequentialInputs[*updater.Certificate, pip.None](),
		pip.WithOnNoMoreData[*updater.Certificate, pip.None](func() ([]pip.None, []int, error) {
			p.certSinkHasNoMoreData = true // Flag that the pipeline has no more data to process.
			return nil, nil, nil
		}),
		pip.WithSinkFunction(func(in *updater.Certificate) error {
			if in == nil {
				return nil
			}
			var err error
			certProcessedCount++
			p.stats.WrittenCerts.Add(1)
			p.stats.WrittenBytes.Add(int64(len(in.Cert.Raw)))

			if certProcessedCount >= p.BundleSize {
				// Reset counters.
				certProcessedCount = 0
				// Request the next stages to stop.
				err = pip.NoMoreData
			}
			return err
		}),
	)
}
