# Ingest

`cmd/ingest` is the bulk certificate ingestion command used to read CT-exported `.csv` and
`.gz` bundles, transform them into certificate/domain rows, and insert them into the DB through
CSV-backed batch loaders.

This document is intentionally more internal than the root repository README. It is aimed at
engineers debugging ingest behavior, changing the pipeline, or investigating throughput and
memory regressions.
This document is written by an LLM, and reviewed by a human. It is also intended for the LLMs to consume.

## Purpose And Scope

The ingest command is optimized for high-throughput, batched ingestion into partitioned DB
tables. It is not designed around single-certificate writes, minimal-memory execution, or
interactive workflows.

At a high level, ingest:

1. Builds the list of pending files from the journal.
2. Splits that file list into batches.
3. For each file batch, constructs a fresh `Processor`.
4. The `Processor` builds:
   - a files' pipeline from CSV bundles to `updater.Certificate`
   - a DB pipeline inside `updater.Manager`
5. Joins both pipelines, runs them, waits for completion, and then moves on to the next file
   batch.

The command can optionally continue with coalescing and SMT update work after ingestion, depending
on `-strategy`.

## Batch Lifecycle

The unit of work for the runtime lifecycle is the file batch, not the whole directory.

For each batch:

1. `mainFunction` creates one new `Processor`.
2. `NewProcessor` creates one new `updater.Manager`.
3. The `Processor` creates the file-reading/parsing pipeline.
4. The `Manager` creates the DB-facing worker pipeline.
5. Both pipelines are joined into a single pipeline owned by the `Processor`.
6. `Processor.Resume()` starts the joined pipeline.
7. `Processor.Wait()` waits until the joined pipeline finishes or returns an error.
8. After the batch completes, the `Processor`, `Manager`, and all worker-owned storage are
   expected to become unreachable, so the next batch starts from a fresh runtime instance.

This last point is important: ingest depends on old per-batch processors/managers becoming
collectible. If previous batches remain reachable, memory usage grows batch after batch even if
each individual batch has bounded storage.

## Pipeline Architecture

The file-side pipeline is created in `cmd/ingest/processor.go`:

- source: emits `util.CsvFile`
- splitter workers: emit CSV lines
- parse workers: emit parsed chain data
- chain-to-cert workers: emit `updater.Certificate`
- sink: records statistics

The DB-side pipeline is created in `pkg/mapserver/updater/manager.go`:

- source: receives `updater.Certificate`
- cert batchers and cert CSV workers
- domain extractors, domain batchers, and domain CSV workers
- DB inserters and temp-file removers

The joined pipeline keeps:

- the source from the files' pipeline
- the internal active stages from both pipelines
- the sinks from the DB pipeline

The files-side cert output stages are rewired to forward each certificate to the manager's source
fan-out logic. This avoids using the generic `JoinTwoPipelines` path in the hot ingest path.

### Active vs Skipped Stages when Joining Pipelines

The join logic must distinguish between:

- active stages, which are part of the runtime lifecycle of the joined pipeline
- skipped stages, which still need enough channel initialization to be linked correctly, but must
  not run source/sink-specific lifecycle code if they are not resumed as active members of the
  joined pipeline

This distinction is subtle and important. A previous bug prepared skipped source stages as if they
were active runtime stages. That spawned source goroutines that were never part of the joined
pipeline's normal shutdown path, which in turn kept old processors/managers reachable across file
batches.

## Ownership And Reachability Assumptions

The current implementation assumes the following ownership rules:

- one `Processor` owns one joined pipeline
- one `Processor` owns one `Manager`
- one `Manager` owns one DB pipeline and its worker-local storage
- worker-local storage is intentionally reused within the lifetime of that one manager
- once `Processor.Wait()` returns and batch-level references are dropped, the whole object graph
  for that batch should become collectible

In practice, that means:

- large worker allocations are acceptable only if they are bounded to one live batch
- leaks in stage lifecycle or goroutines are especially expensive, because they retain whole
  managers and their worker caches
- debugging memory regressions should focus on reachability, not only allocation size

## Memory Model And Known Retention Hazards

Ingest intentionally keeps significant per-batch storage live to maximize throughput:

- parser-side certificate de-duplication caches
- cert batch ring buffers
- domain batch ring buffers
- preallocated CSV row storage
- temporary filepath ring caches

These are throughput-oriented allocations, not accidents. They become a problem when either:

1. too much data is live at once within the active batch, or
2. data from older batches remains reachable when it should have been freed

### Historical Join Leak
(Updated on 1.04.2026.)

One important historical failure mode was the joined-pipeline leak mentioned above:

- skipped source stages were prepared like active stages
- source preparation spawned goroutines
- those goroutines kept the skipped sources reachable
- the skipped sources retained closures pointing into old manager instances
- the old manager instances retained their pipelines and all worker storage

The result was memory growth across batches that looked like worker-local storage "growing
forever", even though the real problem was that whole old batch pipelines were still reachable.

### Ring Buffer Retention

Worker ring buffers reuse backing arrays across rotations. That reuse is necessary for throughput,
but it also means rotation logic must not keep old payload references alive longer than intended.

If rotated entries are only resliced to length zero, but not cleared, backing arrays can still
retain references such as:

- certificate `Raw []byte`
- certificate `Names []string`
- domain `Name string`

This is a bounded-within-batch retention issue, not necessarily an unbounded leak on its own, but
it can still materially increase the working set of an active batch.

## Important Tuning Flags

The main ingest flags are intentionally coupled to throughput assumptions.

- `-numdbworkers`
  Usually aligned with the DB partition count. The common production assumption is `32` workers
  for `32` partitions, so inserts can proceed in parallel.

- `-multiinsert`
  Controls batch sizes for cert/domain worker pipelines and CSV generation. Historically values
  around `10000` were chosen for throughput, but this should be revalidated whenever the insertion
  path changes. CSV-backed ingestion may have a different optimum than older insertion modes.

- `-numparsers`
  Controls parser parallelism. Higher values increase throughput potential but also increase
  parsing-side memory pressure and cache footprint.

- `-numfiles`
  Controls how many input files are read in parallel. This affects how many file readers and line
  splitters are active simultaneously.

- `-filebatch`
  Controls how many files belong to one runtime batch. This directly determines how often a new
  processor/manager pair is created and therefore how often the runtime lifecycle must reset
  cleanly.

### Tuning Tradeoffs

The guiding principle is not "minimize memory at all costs". The goal is:

- keep the DB and CSV pipeline saturated
- preserve partition-aware parallelism
- keep per-batch memory bounded
- ensure old batches are collectible

Reducing worker counts or batch sizes can lower memory, but may also reduce throughput.
Treat memory regressions first as a correctness issue in object lifetime, then as a tuning issue.

## Diagnostics Workflow

When investigating ingest memory behavior, use runtime diagnostics.

Recommended workflow:

1. Run ingest with production-like flags.
2. Trigger diagnostics with `SIGUSR1`, or collect them on termination.
3. Inspect:
   - `memstats.txt`
   - `heap.pprof`
   - `heap-after-gc.pprof`
   - `allocs.pprof`
   - `goroutines.txt`
   - `meta.txt`
4. Compare:
   - live heap after GC
   - dominant in-use sites
   - goroutine counts and ages
   - whether old batch/runtime structures appear to accumulate

Check the following:

- is the live heap dominated by current-batch parsing/storage, or by retained old batches?
- do goroutine dumps show old pipeline/source goroutines still alive after many batches?
- are the largest allocations expected throughput-oriented structures, or accidental long-lived
  references?

Heap profiles and goroutine dumps are the source of truth for memory regressions.

## Limitations And Invariants

The current ingest command assumes:

- ingestion is batch-oriented
- DB insertion is optimized for CSV-backed bulk loading
- throughput matters enough to justify large worker-local preallocations
- worker sharding follows DB partitioning assumptions

Non-goals and limitations:

- ingest is not optimized for one-certificate-at-a-time insertion
- low-memory execution is not the primary optimization target
- changing the insertion mode may invalidate historical tuning choices such as `-multiinsert`
- lifecycle bugs in the joined pipeline can dominate memory behavior even when worker-local code is
  individually reasonable

When changing ingest internals, preserve these invariants unless intentionally redesigning
the command, and have fresh benchmarks and diagnostics to support that redesign.
