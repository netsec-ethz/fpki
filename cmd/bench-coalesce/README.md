# Coalescing Benchmark

This command benchmarks the old and new versions of the `calc_dirty_domains` stored procedure under a deterministic synthetic workload. It is meant to answer a narrow question:

- How much faster is the new coalescing procedure than the old one?
- Does the speedup still hold when the generated workload is skewed across partitions?
- What does cleanup of stale dirty domains cost?

The benchmark lives in [`main.go`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/main.go).

The benchmark binary is self-contained with respect to the stored-procedure snapshots:

- the `calc_dirty_domains_*.sql` files are embedded into the binary at build time
- you can copy just the built benchmark binary to another machine and run it there
- you do not need to copy the SQL files alongside it

## What It Benchmarks

The headline benchmark exercises the production Go call path:

- [`updater.CoalescePayloadsForDirtyDomains`](/home/juagargi/devel/ETH/fpki/pkg/mapserver/updater/updater.go)
- [`RecomputeDirtyDomainsCertAndPolicyIDs`](/home/juagargi/devel/ETH/fpki/pkg/db/mysql/dirty.go)
- `CALL calc_dirty_domains(?)` over all 32 partitions

The procedure variants are loaded from:

- [`calc_dirty_domains_old.sql`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/testdata/calc_dirty_domains_old.sql)
- [`calc_dirty_domains_rewrite_only.sql`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/testdata/calc_dirty_domains_rewrite_only.sql)
- [`calc_dirty_domains_new.sql`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/testdata/calc_dirty_domains_new.sql)

At runtime, the command reads embedded copies of those SQL files from `cmd/bench-coalesce/testdata`.

The command compares:

- `old`: the pre-rewrite procedure from `ad22b3f2`
- `new`: the current procedure with stale-row cleanup from `51bf4423`
- `rewrite_only`: the intermediate rewrite from `3b3ce935`, used only for medium-size diagnostics

## Workload Shape

Each size always includes:

- 0.5% stale dirty domains

The rest of the workload depends on two flags:

- `-partition-skew`: controls how unevenly active domains, and therefore cert/policy rows, are distributed across partitions
- `-balance`: controls how many active domains also get policy chains

The per-domain shapes are fixed:

- Cert-only domain: 2 leaf cert links, expanding to 4 cert IDs after recursive closure
- Mixed domain: the same cert shape plus 1 policy chain, expanding to 3 policy IDs
- Stale domain: a row already exists in `domain_payloads` and `domains`, the domain is still in `dirty`, but the cert/policy link rows are gone

### `-partition-skew`

Allowed values:

- `no`: almost uniform distribution across all 32 partitions
- `little`: 2 partitions get 10% fewer active rows than the other 30
- `large`: 16 partitions get 25% fewer active rows than the other 16

The implementation is deterministic:

- `little` reduces partitions `p30` and `p31`
- `large` reduces partitions `p16` through `p31`

### `-balance`

`-balance` is the percentage of generated policy IDs with respect to generated certificate IDs.

Examples:

- `-balance 0`: no policy chains are generated
- `-balance 25`: generate enough mixed domains so policy IDs are roughly 25% of certificate IDs
- `-balance 75`: every active domain becomes mixed, which is the maximum achievable ratio with the current domain shapes

Why the maximum is 75:

- Every active domain always contributes 4 certificate IDs
- A mixed domain adds 3 policy IDs
- So the highest possible policy/certificate ratio is `3/4 = 75%`

## How It Works

At a high level, the command does this for each selected size:

1. Build one deterministic fixture on disk as CSV files.
2. For each run, create a fresh benchmark database.
3. Install one procedure variant into that database.
4. Load the exact same fixture into the fresh database.
5. Run coalescing once.
6. Validate the output.
7. Drop the database, unless `-keep-databases` is set.

Important implementation details:

- Fixture generation happens once per size in `buildFixture`.
- Database names are generated only by `benchmarkDBName`.
- Databases are created only by `createBenchmarkDB`.
- Stored-procedure SQL is loaded from files embedded into the benchmark binary.
- `createBenchmarkDB` runs the schema bootstrap by sending `create_new_db <dbName>` to the embedded `create_schema.sh` script.
- Fixture loading checks `@@GLOBAL.secure_file_priv`; if MySQL restricts `LOAD DATA INFILE` to a specific directory, the benchmark copies the generated CSVs there automatically before loading them.
- The measured phase uses a fresh DB connection after fixture loading so the setup session is separated from the measured session.

## How To Run It

Run all default sizes and diagnostics:

```bash
go run ./cmd/bench-coalesce
```

Run only the small dataset:

```bash
go run ./cmd/bench-coalesce -sizes small
```

Run with a larger skew and a 50% policy/certificate balance:

```bash
go run ./cmd/bench-coalesce -sizes medium -partition-skew large -balance 50
```

Run with fewer concurrent coalescing workers to reduce server-side temporary-file pressure:

```bash
go run ./cmd/bench-coalesce -sizes medium,large -coalesce-workers 8
```

Run a short smoke benchmark:

```bash
go run ./cmd/bench-coalesce -sizes small -warmup-pairs 0 -measured-pairs 1 -skip-diagnostics
```

Run only medium, keeping diagnostics:

```bash
go run ./cmd/bench-coalesce -sizes medium
```

Keep generated fixture CSVs for inspection:

```bash
go run ./cmd/bench-coalesce -keep-artifacts
```

Keep benchmark databases after the run for manual SQL inspection:

```bash
go run ./cmd/bench-coalesce -keep-databases
```

Change the fixture directory:

```bash
go run ./cmd/bench-coalesce -temp-dir /tmp/my-coalesce-bench
```

## Flags

- `-sizes`: comma-separated subset of `small,medium,large`
- `-warmup-pairs`: number of warmup old/new pairs per size
- `-measured-pairs`: number of measured old/new pairs per size
- `-medium-diagnostic-runs`: number of full `rewrite_only` medium runs
- `-partition-skew`: one of `no`, `little`, `large`
- `-balance`: integer percentage from `0` to `75`
- `-coalesce-workers`: concurrent partition workers used for full runs; defaults to `8`
- `-skip-diagnostics`: skip `rewrite_only` and per-partition medium diagnostics
- `-keep-artifacts`: keep generated CSV fixtures
- `-keep-databases`: keep benchmark schemas after the command exits
- `-temp-dir`: directory used for generated fixture files

## How To Read The Output

The command prints two main sections.

### Full-run summary

This is the headline comparison. For each size and each variant, it prints:

- a workload header with the selected `partition-skew` and `balance`
- the workload header also shows `coalesce-workers`
- a compact per-size workload table showing active, cert-only, mixed, and stale domain counts
- `median`: median wall-clock runtime across measured samples
- `IQR`: interquartile range of runtime, as a quick stability check
- `dirty/s`: dirty domains processed per second
- `active/s`: non-stale dirty domains processed per second

Then it prints a compact `new vs old` summary:

- `old`: median runtime of the old procedure
- `new`: median runtime of the current procedure
- `new vs old`: percentage speedup, computed from the medians

Interpretation:

- Lower `median` is better
- Smaller `IQR` means more stable runs
- Higher `dirty/s` and `active/s` are better
- A positive `new vs old` percentage means the new procedure is faster
- If `balance=0`, the command prints an explicit note that this is a cert-only workload; that case can legitimately favor the old procedure because policy aggregation is absent and fixed cleanup overhead is more visible

### Medium diagnostics

This section helps explain why the headline result looks the way it does.

It includes:

- `rewrite_only` full-run timings on the medium dataset
- Per-partition timings for the current procedure on the medium dataset

Use this section to answer:

- Is most of the gain from the rewrite itself, or from cleanup?
- Are hot partitions much slower than cold ones?
- Does the chosen `-partition-skew` visibly change the tail?
- Is total runtime dominated by a small number of partitions?

The partition summary includes:

- `min`: fastest partition
- `p50`: median partition runtime
- `p95`: tail partition runtime
- `max`: slowest partition

If `p95` and `max` are much larger than `p50`, the workload is strongly skewed and the hotter partitions dominate.

## Why This Can Be Run On The Production Machine

This command was written to avoid touching the production `fpki` schema.

The key safety properties are concrete and easy to verify in code:

- Database names are produced only by [`benchmarkDBName`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/main.go), which always returns names starting with `bench_coalesce_`.
- Those generated names also include the selected size, skew, and balance values.
- Databases are created only by [`createBenchmarkDB`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/main.go).
- `createBenchmarkDB` invokes the schema helper by writing `create_new_db <dbName>` to the script stdin.
- The `<dbName>` used there is always the benchmark-prefixed name from `benchmarkDBName`.
- Connections for benchmark work are opened only through [`connectBenchmarkDB`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/main.go), which connects to the generated benchmark schema name.
- Cleanup is handled by [`dropBenchmarkDB`](/home/juagargi/devel/ETH/fpki/cmd/bench-coalesce/main.go), which drops only that generated benchmark schema name.

What this means in practice:

- The benchmark does not call `create_new_db fpki`
- The benchmark does not reuse the long-lived production DB
- The benchmark does not benchmark in-place against production tables
- Each sample is isolated in its own throwaway benchmark schema

You should still use normal operational judgment:

- Run it during a period where extra MySQL CPU and IO load is acceptable
- Avoid running multiple copies in parallel
- Prefer `-sizes small` or a short smoke run first if you are validating the setup

## Validation Per Run

Each measured run validates that:

- Active domains produce the expected aggregated cert/policy payload IDs
- The row counts match the chosen variant behavior
- Stale rows are removed when the variant is expected to remove them

That validation is important because the benchmark is comparing implementations, not just timing them.

## Typical Workflow

1. Run a smoke command to confirm MySQL connectivity and permissions.
2. Run `small` first to validate the environment.
3. Run the full benchmark.
4. Compare the full-run summary.
5. Use the medium diagnostics to explain where the speedup comes from.

Example:

```bash
go run ./cmd/bench-coalesce -sizes small -warmup-pairs 0 -measured-pairs 1 -skip-diagnostics
go run ./cmd/bench-coalesce
go run ./cmd/bench-coalesce -sizes medium -partition-skew little -balance 25
```
