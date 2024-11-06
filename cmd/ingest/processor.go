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
	Ctx              context.Context
	CsvFiles         []util.CsvFile
	NumFileReaders   int
	NumToChain       int
	NumToCerts       int
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
		Ctx:              ctx,
		NumFileReaders:   1,              // Default to 1 file reader.
		NumToChain:       1,              // Default to just 1 lineToChain.
		NumToCerts:       1,              // Default to just 1 chainToCerts.
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
	manager, err := updater.NewManager(
		p.NumDBWriters,
		conn,
		multiInsertSize,
		statsUpdatePeriod,
		statsUpdateFun,
	)
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

func WithNumFileReaders(numFileReaders int) processorOptions {
	return func(p *Processor) {
		p.NumFileReaders = numFileReaders
	}
}

func WithNumToChains(numWorkers int) processorOptions {
	return func(p *Processor) {
		p.NumToChain = numWorkers
	}
}

func WithNumToCerts(numWorkers int) processorOptions {
	return func(p *Processor) {
		p.NumToCerts = numWorkers
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
	p.Pipeline.Resume(p.Ctx)
}

func (p *Processor) Wait() error {
	return p.Pipeline.Wait(p.Ctx)
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
//	a: source, generates CsvFile, crisscross output.
//	b1..S: transforms into lines, crisscross I/O. csvSplitWorker.
//	c1..W: transforms into Chain, crisscross I/O. lineToChainWorker.
//	d1..C: transforms into []Certificate, crisscross I/O. chainToCertWorker.
//	e: sink, multiple inputs, crisscross input. []Certificate.
//
// The indices are below:
// a: 0
// b: 1..S
// c: 1+S..1+S+W
// d: 1+S+W..1+S+W+C
// e: 1+S+W+C
//
//	a ┌-> b1 -┌-> c1 ---> d1 -┬-> e
//	  |-> b2  |-> c2 ---> d2 -|
//	 ...     ...             ...
//	  └-> bw -┴-> cw ---> dw -┘
func (p *Processor) createFilesToCertsPipeline() (*pip.Pipeline, error) {
	// Prepare source. It opens CSV files based on the filenames stored in the processor.
	source := pip.NewSource[util.CsvFile](
		"open-csv-files",
		pip.WithSourceSlice(&p.CsvFiles, func(in util.CsvFile) (int, error) {
			return 0, nil
		}),
	)
	sourceFunc := source.ProcessFunc
	source.ProcessFunc = func(in pip.None) ([]util.CsvFile, []int, error) {
		_, span := source.Tracer.Start(source.Ctx, "file")
		outs, chans, err := sourceFunc(in)
		span.End()
		return outs, chans, err
	}

	// Create CSV split worker.
	splitters := make([]*csvSplitWorker, p.NumFileReaders)
	for i := range splitters {
		splitters[i] = NewCsvSplitWorker(p)
	}

	// Create numParsers toChain workers. Parses lines into chains.
	lineToChainWorkers := make([]*lineToChainWorker, p.NumToChain)
	for i := range lineToChainWorkers {
		lineToChainWorkers[i] = NewLineToChainWorker(p, i)
	}

	// Create chain to certificates worker.
	chainToCertWorkers := make([]*chainToCertWorker, p.NumToCerts)
	for i := range chainToCertWorkers {
		chainToCertWorkers[i] = NewChainToCertWorker(i)
	}

	// Create sink for certificate pointers.
	sink := p.createCertificateSink()

	stages := []pip.StageLike{
		source,
	}
	for _, w := range splitters {
		stages = append(stages, w.Stage)
	}
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
				a: source, generates CsvFile
				b: transforms into line, multiple outputs.
				c1..W: transforms into Chain.
				d1..W: transforms into []Certificate.
				e: sink, multiple inputs.
			The indices are below:
			a: 0
			b: 1..S
			c: 1+S..1+S+W
			d: 1+S+W..1+S+W+C
			e: 1+S+2W

			a ┌-> b1 -┌-> c1 -┌-> d1 -┬-> e
			  |-> b2 -|-> c2 -|-> d2 -|
			 ...     ...     ...     ...
			  └-> bS -┴-> cW -┴-> dC -┘

			*/
			S := p.NumFileReaders
			W := p.NumToChain
			C := p.NumToCerts
			a := pip.SourceStage[util.CsvFile](pipeline)
			b := make([]*pip.Stage[util.CsvFile, line], S)
			for i := range b {
				b[i] = pip.StageAtIndex[util.CsvFile, line](pipeline, 1+i)
			}
			c := make([]*pip.Stage[line, certChain], W)
			for i := range c {
				c[i] = pip.StageAtIndex[line, certChain](pipeline, 1+S+i)
			}
			d := make([]*pip.Stage[certChain, updater.Certificate], C)
			for i := range d {
				d[i] = pip.StageAtIndex[certChain, updater.Certificate](pipeline, 1+S+W+i)
			}
			e := []*pip.Stage[updater.Certificate, pip.None]{pip.SinkStage[updater.Certificate](pipeline)}

			pip.LinkStagesDistribute(a, b...) // A -> B
			pip.LinkStagesCrissCross(b, c)    // Bi-> Ci
			pip.LinkStagesCrissCross(c, d)    // Ci-> Di
			pip.LinkStagesCrissCross(d, e)    // Di-> E
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
