package main

import (
	"context"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
	pip "github.com/netsec-ethz/fpki/pkg/pipeline"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/netsec-ethz/fpki/pkg/util/debug"
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
	Ctx               context.Context
	CsvFiles          []util.CsvFile
	NumFileReaders    int
	NumToChain        int
	NumToCerts        int
	NumDBWriters      int
	Pipeline          *pip.Pipeline
	Manager           *updater.Manager
	bundleSize        uint64
	onBundleFinished  func()
	certsBeforeBundle atomic.Uint64
	doingBundle       atomic.Bool
}

func NewProcessor(
	ctx context.Context,
	conn db.Conn,
	multiInsertSize int,
	statsUpdatePeriod time.Duration,
	statsUpdateFun func(*updater.Stats),
	options ...ingestOptions,
) (*Processor, error) {
	// Create the processor that will hold all the information and the pipeline.
	p := &Processor{
		Ctx:            ctx,
		NumFileReaders: 1, // Default to 1 file reader.
		NumToChain:     1, // Default to just 1 lineToChain.
		NumToCerts:     1, // Default to just 1 chainToCerts.
		NumDBWriters:   1, // Default to 1 db writer.

		bundleSize:        math.MaxUint64,
		onBundleFinished:  func() {}, // Noop.
		certsBeforeBundle: atomic.Uint64{},
		doingBundle:       atomic.Bool{},
	}

	// Apply options to processor only.
	for _, opt := range options {
		if opt, ok := opt.(processorOptions); ok {
			opt(p)
		}
	}

	// Create the DB manager.
	var err error
	p.Manager, err = updater.NewManager(
		p.NumDBWriters,
		conn,
		multiInsertSize,
		math.MaxUint64, // = infinite per default.
		func() {},      // onBundle: defaults to noop.
		statsUpdatePeriod,
		statsUpdateFun,
	)
	if err != nil {
		return nil, err
	}

	// Apply options to processor only.
	for _, opt := range options {
		if opt, ok := opt.(managerOptions); ok {
			opt(p.Manager)
		}
	}

	// Create the pipFiles from files to Certificates.
	pipFiles, err := p.createFilesToCertsPipeline()
	if err != nil {
		return nil, err
	}

	// Join the two pipelines.
	pipeline := pip.JoinPipelinesRaw(
		p.getNewLinkFunction(pipFiles, p.Manager.Pipeline),
		pipFiles,
		p.Manager.Pipeline,
	)

	// At the chainToCert stages we evaluate if need to stop. These stages are the last ones right
	// before the sink, with NumToCerts number of them.
	evaluateAt := make([]int, 0, p.NumToCerts)
	for i := len(pipFiles.Stages); i > len(pipFiles.Stages)-p.NumToCerts; i-- {
		evaluateAt = append(evaluateAt, i-2)
	}

	stallOption := pip.WithStallStages(
		append(pipFiles.Stages, p.Manager.Pipeline.Stages...), // all stages, both pipelines.
		// Function when stalled:
		func() {
			// Call the function.
			p.onBundleFinished()

			// Reset the counter.
			p.certsBeforeBundle.Store(0)
			// Reset the bundle running indicator.
			p.doingBundle.Store(false)
		},
		// Function determining when to stall:
		func(sl pip.StageLike) bool {
			if p.certsBeforeBundle.Load() > p.bundleSize && p.doingBundle.CompareAndSwap(false, true) {
				return true
			}
			return false
		},
		// Evaluate at every chainToCerts stage.
		pipFiles.StagesAt(evaluateAt...),
	)
	stallOption(pipeline)

	// Set the joint pipeline as the pipeline and return.
	p.Pipeline = pipeline
	return p, nil
}

type ingestOptions interface{}
type processorOptions func(*Processor)
type managerOptions func(*updater.Manager)

func WithNumFileReaders(numFileReaders int) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			p.NumFileReaders = numFileReaders
		})
}

func WithNumToChains(numWorkers int) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			p.NumToChain = numWorkers
		})
}

func WithNumToCerts(numWorkers int) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			p.NumToCerts = numWorkers
		})
}

func WithNumDBWriters(numDBWriters int) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			p.NumDBWriters = numDBWriters
		})
}

func WithBundleSize(bundleSize uint64) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			if bundleSize == 0 {
				bundleSize = math.MaxUint64
			}
			p.bundleSize = bundleSize
		})
}

func WithOnBundleFinished(fcn func()) ingestOptions {
	return processorOptions(
		func(p *Processor) {
			p.onBundleFinished = fcn
		})
}

func (p *Processor) Resume() {
	p.Pipeline.Resume(p.Ctx)
}

func (p *Processor) Wait() error {
	err := p.Pipeline.Wait(p.Ctx)
	// Check if there is a bundle pending.
	if p.certsBeforeBundle.Load() > 0 {
		p.onBundleFinished()
	}
	return err
}

// AddGzFiles adds a CSV .gz file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddGzFiles(fileNames []string) {
	p.Manager.Stats.TotalFiles.Add(int64(len(fileNames)))

	for _, filename := range fileNames {
		p.CsvFiles = append(p.CsvFiles, (&util.GzFile{}).WithFile(filename))
	}
}

// AddCsvFiles adds a .csv file to the initial stage.
// It blocks until it is accepted.
func (p *Processor) AddCsvFiles(fileNames []string) {
	p.Manager.Stats.TotalFiles.Add(int64(len(fileNames)))

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
//	  └-> bS -┴-> cW ---> dC -┘
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
		chainToCertWorkers[i] = NewChainToCertWorker(i, p)
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
	)

	return pipeline, err
}

func (p *Processor) createCertificateSink() *pip.Sink[updater.Certificate] {
	return pip.NewSink[updater.Certificate](
		"certSink",
		pip.WithSinkFunction(func(in updater.Certificate) error {
			p.Manager.Stats.WrittenCerts.Add(1)
			p.Manager.Stats.WrittenBytes.Add(int64(len(in.Cert.Raw)))

			return nil
		}),
	)
}

func (p *Processor) createCertificatePtrSink() *pip.Sink[*updater.Certificate] {
	return pip.NewSink[*updater.Certificate](
		"certSink",
		pip.WithSinkFunction(func(in *updater.Certificate) error {
			if in == nil {
				return nil
			}
			p.Manager.Stats.WrittenCerts.Add(1)
			p.Manager.Stats.WrittenBytes.Add(int64(len(in.Cert.Raw)))

			return nil
		}),
	)
}

// getNewLinkFunction links the first with the second pipeline overriding the sink and source of
// the first and second pipeline, respectively.
//
//	The first pipeline looks like:
//	a ┌-> b1 -┌-> c1 ---> d1 -┬-> e
//	  |-> b2  |-> c2 ---> d2 -|
//	 ...     ...             ...
//	  └-> bS -┴-> cW ---> dC -┘
//
// The stages previous to the sink are crisscross linked to the sink, with NumToCerts count.
//
//	The second pipeline looks like:
//	a -┌-> b1 ---> c1
//	   |-> b2 ---> c2
//	  ...
//	   |-> bw ---> cw
//	   |
//	   |-> d1 -┬-> e1 ---> f1
//	   |-> d2 -|-> e2 ---> f2
//	  ...     .|.         ...
//	   └-> dw -┴-> ew ---> fw
//
// With the source sending duplicate outputs to b and d depending on its own source function.
// Thus the source has 2*NumDBWriters out channels.
// We could link p1.sink.incoming to be the same as the p2.source.sourceChannel, but that is
// exactly what the pip.JoinTwoPipelines does and it has performance issues.
// What we do instead is replace each output channel of p1.di with a new one, that receives the
// Certificate and run the p2.source.sourceProcessFunc to obtain the next two stages at p2.
func (p *Processor) getNewLinkFunction(
	filesPipeline *pip.Pipeline,
	dbPipeline *pip.Pipeline,
) func(*pip.Pipeline) {
	return func(*pip.Pipeline) {
		// First link both pipelines as usual.
		filesPipeline.LinkFunction()(filesPipeline)
		dbPipeline.LinkFunction()(dbPipeline)

		// Find the ToCerts stages.
		toCerts := make([]*pip.Stage[certChain, updater.Certificate], 0)
		for _, s := range filesPipeline.Stages {
			s, ok := s.(*pip.Stage[certChain, updater.Certificate])
			if ok {
				toCerts = append(toCerts, s)
			}
		}
		if len(toCerts) != p.NumToCerts {
			// We should have exactly NumToCerts stages.
			panic(fmt.Errorf("logic error %d != %d", len(toCerts), p.NumToCerts))
		}

		// Obtain the incoming channels of both the cert batchers and domain extractors.
		// This is equivalent to obtaining the out channels of p2.source.
		source := dbPipeline.Source.(*pip.Source[updater.Certificate])
		if len(source.OutgoingChs) != 2*p.NumDBWriters {
			// We should have exactly twice NumDBWriters channels.
			panic(fmt.Errorf("logic error %d != 2*%d", len(source.OutgoingChs), p.NumDBWriters))
		}

		// Error channels:

		// Link the error channels, as many as receivers of errors.
		errChs := make([]chan error, p.NumToCerts)
		for i := range errChs {
			errChs[i] = make(chan error)
		}
		for i := range toCerts {
			toCerts[i].NextErrChs[0] = errChs[i]
		}
		// For each error received from the second pipeline, send an error to the first one.
		wgErrChs := sync.WaitGroup{}
		wgErrChs.Add(len(source.NextErrChs))
		for _, errCh := range source.NextErrChs {
			errCh := errCh
			go func() {
				defer wgErrChs.Done() // Signal that this error channel is closed.
				for err := range errCh {
					util.SendToAllChannels(errChs, err)
				}
			}()
		}
		// Once all error channels from p2 are closed, close all error channels.
		go func() {
			wgErrChs.Wait()
			for _, errCh := range errChs {
				close(errCh)
			}
		}()

		// Data channels:

		// Create as many new data channels as NumToCerts stages.
		chans := make([]chan updater.Certificate, p.NumToCerts)
		for i := range chans {
			chans[i] = make(chan updater.Certificate)
		}

		// Link toCerts' out channels to the new channels.
		// Restore the default behavior of closing the output channel (ignore crisscross).
		for i := range toCerts {
			toCerts[i].OutgoingChs[0] = chans[i]
			opt := pip.WithCloseOutChannelFunc[certChain, updater.Certificate](func(index int) {
				close(toCerts[i].OutgoingChs[index])
			})
			opt.ApplyToStage(toCerts[i])
		}

		// Now send each Certificate to both bi and di stages, according to the p2.source.sourceFunc.
		sourceFunc := source.SourceProcessFunc()

		// For each of the out channels of the first pipeline.
		wg := sync.WaitGroup{}
		wg.Add(len(chans))
		for _, ch := range chans {
			ch := ch
			go func() {
				defer wg.Done() // Signal that another output channel has been closed.
				// For each Certificate that the first pipeline outputs.
				pip.DebugPrintf("[processor] listening on data channel %s\n", debug.Chan2str(ch))
				for in := range ch {
					pip.DebugPrintf("[processor] got value on channel %s\n", debug.Chan2str(ch))
					// Get the indices of the correct cert batcher and domain extractor to send it.
					chs, err := sourceFunc(in)
					_ = err // ignore error

					// Send both in parallel.
					util.SendToAllChannels(
						[]chan updater.Certificate{
							source.OutgoingChs[chs[0]],
							source.OutgoingChs[chs[1]],
						},
						in)
				} // for each Certificate.
				pip.DebugPrintf("[processor] incoming channel %s is closed\n", debug.Chan2str(ch))
			}()
		} // for each output channel.

		// Once all output channels have been closed, close all incoming channels of p2.
		go func() {
			wg.Wait()
			for _, ch := range source.OutgoingChs {
				pip.DebugPrintf("[processor] closing data channel %s\n", debug.Chan2str(ch))
				close(ch)
			}
		}()
	}
}
