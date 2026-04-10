package main

// bench-coalesce benchmarks old vs new versions of the calc_dirty_domains stored procedure.
//
// How to run:
//   go run ./cmd/bench-coalesce
//   go run ./cmd/bench-coalesce -sizes small
//   go run ./cmd/bench-coalesce -sizes medium -warmup-pairs 1 -measured-pairs 2
//   go run ./cmd/bench-coalesce -sizes small -skip-diagnostics
//   go run ./cmd/bench-coalesce -sizes medium -partition-skew large -balance 50
//   go run ./cmd/bench-coalesce -sizes medium -coalesce-workers 8
//
// Safety notes:
//   - The benchmark does not connect to or mutate the production "fpki" schema.
//   - Every benchmark sample creates its own fresh schema through createBenchmarkDB.
//   - createBenchmarkDB executes the embedded create_schema.sh helper by writing exactly
//     "create_new_db <dbName>" to its stdin, where <dbName> always comes from benchmarkDBName.
//   - benchmarkDBName always prefixes schemas with "bench_coalesce_", so this command only
//     creates benchmark-specific databases such as "bench_coalesce_old_small_pair_01_step_1".
//   - Unless -keep-databases is set, each temporary benchmark schema is dropped after the run.
//
// See README.md in this directory for the full benchmark design, examples, and result-reading
// guidance.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/netsec-ethz/fpki/pkg/common"
	"github.com/netsec-ethz/fpki/pkg/db"
	"github.com/netsec-ethz/fpki/pkg/db/mysql"
	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/netsec-ethz/fpki/tools"
)

//go:embed testdata/*.sql
var procedureFiles embed.FS

const (
	partitionCount      = 32
	staleNamePrefix     = "stale-"
	certOnlyNamePrefix  = "cert-"
	mixedNamePrefix     = "mixed-"
	domainNameSuffix    = ".bench.test"
	timeLayout          = "2006-01-02 15:04:05"
	writerBufferSize    = 8 * 1024 * 1024
	fullRunTimeout      = 2 * time.Hour
	partitionRunTimeout = 30 * time.Minute
)

type variant struct {
	Name             string
	ProcedurePath    string
	ExpectDomainRows bool
	ExpectStaleGone  bool
	Chunked          bool
	ChunkSize        int
}

var (
	oldVariant = variant{
		Name:             "old",
		ProcedurePath:    "calc_dirty_domains_old.sql",
		ExpectDomainRows: true,
		ExpectStaleGone:  false,
	}
	rewriteVariant = variant{
		Name:             "rewrite_only",
		ProcedurePath:    "calc_dirty_domains_rewrite_only.sql",
		ExpectDomainRows: true,
		ExpectStaleGone:  true,
	}
	newVariant = variant{
		Name:             "new",
		ProcedurePath:    "calc_dirty_domains_new.sql",
		ExpectDomainRows: false,
		ExpectStaleGone:  true,
		Chunked:          true,
		ChunkSize:        20000,
	}
	headlineVariants = []variant{oldVariant, newVariant}
)

type sizeSpec struct {
	Name         string
	DirtyDomains int
}

type config struct {
	WorkDir         string
	TempDir         string
	Sizes           []sizeSpec
	WarmupPairs     int
	MeasuredPairs   int
	MediumDiagRuns  int
	PartitionSkew   string
	Balance         int
	CoalesceWorkers int
	KeepArtifacts   bool
	KeepDatabases   bool
	SkipDiagnostics bool
}

type fixture struct {
	SizeName              string
	DirtyDomains          int
	ActiveDomains         int
	CertOnlyDomains       int
	MixedDomains          int
	StaleDomains          int
	ExpectedPayloadRows   int
	ExpectedDomainRowsNew int
	PartitionSkew         string
	Balance               int
	Files                 fixtureFiles
	ExpectedRows          []expectedPayloadRow
	PartitionStats        [partitionCount]partitionFixtureStats
}

type fixtureFiles struct {
	Domains        string
	Certs          string
	DomainCerts    string
	Policies       string
	DomainPolicies string
	DomainPayloads string
	Dirty          string
}

type partitionFixtureStats struct {
	DirtyDomains    int
	ActiveDomains   int
	StaleDomains    int
	CertOnlyDomains int
	MixedDomains    int
}

type expectedPayloadRow struct {
	DomainID    common.SHA256Output
	CertIDsID   *common.SHA256Output
	CertLen     int
	PolicyIDsID *common.SHA256Output
	PolicyLen   int
}

type runResult struct {
	Variant                 string
	SizeName                string
	RunLabel                string
	Partition               *int
	Elapsed                 time.Duration
	DirtyPerSecond          float64
	ActivePerSecond         float64
	DomainPayloadRows       int
	DomainRows              int
	RemovedStalePayloadRows int
	RemovedStaleDomainRows  int
}

type sizeRunSummary struct {
	Variant      string
	SizeName     string
	Samples      []runResult
	Median       time.Duration
	IQR          time.Duration
	MedianDirty  float64
	MedianActive float64
}

type pairDelta struct {
	SizeName      string
	OldMedian     time.Duration
	NewMedian     time.Duration
	PercentFaster float64
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "configuration error: %v\n", err)
		os.Exit(2)
	}

	if err := os.MkdirAll(cfg.TempDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	runTempDir, err := prepareRunTempDir(cfg.TempDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create run temp dir: %v\n", err)
		os.Exit(1)
	}
	cfg.TempDir = runTempDir
	if !cfg.KeepArtifacts {
		defer os.RemoveAll(cfg.TempDir)
	}

	fmt.Printf("fixture directory: %s\n", cfg.TempDir)
	fmt.Printf("partition skew: %s | balance: %d%% | coalesce workers: %d\n", cfg.PartitionSkew, cfg.Balance, cfg.CoalesceWorkers)

	// Build each workload once on disk, then replay the exact same rows into fresh databases
	// for every variant/run pair.
	fixtures := make(map[string]*fixture, len(cfg.Sizes))
	for _, size := range cfg.Sizes {
		fmt.Printf("\n== Preparing fixture: %s (%d dirty domains) ==\n", size.Name, size.DirtyDomains)
		fx, err := buildFixture(cfg, cfg.TempDir, size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "build fixture %s: %v\n", size.Name, err)
			os.Exit(1)
		}
		fixtures[size.Name] = fx
	}

	// The headline benchmark exercises the production code path that fans out coalescing over
	// all 32 partitions.
	var fullResults []runResult
	for _, size := range cfg.Sizes {
		fx := fixtures[size.Name]
		fmt.Printf("\n== Full benchmark: %s ==\n", size.Name)

		if err := runWarmups(cfg, fx); err != nil {
			fmt.Fprintf(os.Stderr, "warmups for %s: %v\n", size.Name, err)
			os.Exit(1)
		}
		results, err := runMeasuredPairs(cfg, fx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "measured runs for %s: %v\n", size.Name, err)
			os.Exit(1)
		}
		fullResults = append(fullResults, results...)
	}

	printFullSummary(fullResults, cfg, fixtures)

	// Medium-size diagnostics keep the main comparison compact while still exposing cleanup
	// overhead and partition skew behavior.
	if !cfg.SkipDiagnostics {
		fx, ok := fixtures["medium"]
		if ok {
			fmt.Printf("\n== Medium diagnostics ==\n")
			diagResults, err := runMediumDiagnostics(cfg, fx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "medium diagnostics: %v\n", err)
				os.Exit(1)
			}
			printDiagnosticSummary(diagResults)
		}
	}
}

func parseFlags() (*config, error) {
	var sizeFlag string
	var tempDir string
	cfg := &config{}

	flag.StringVar(&sizeFlag, "sizes", "small,medium,large", "comma-separated sizes to run")
	flag.StringVar(&tempDir, "temp-dir", filepath.Join(os.TempDir(), "fpki-bench-coalesce"), "directory for generated fixture files")
	flag.IntVar(&cfg.WarmupPairs, "warmup-pairs", 2, "number of warmup old/new pairs per size")
	flag.IntVar(&cfg.MeasuredPairs, "measured-pairs", 8, "number of measured old/new pairs per size")
	flag.IntVar(&cfg.MediumDiagRuns, "medium-diagnostic-runs", 4, "number of full-run rewrite_only diagnostic samples on the medium fixture")
	flag.StringVar(&cfg.PartitionSkew, "partition-skew", "no", "certificate/policy partition skew: no, little, or large")
	flag.IntVar(&cfg.Balance, "balance", 0, "percentage of policies with respect to certificates in the generated workload")
	flag.IntVar(&cfg.CoalesceWorkers, "coalesce-workers", 32, "number of concurrent partition workers for full coalescing runs")
	flag.BoolVar(&cfg.KeepArtifacts, "keep-artifacts", false, "keep generated fixture files")
	flag.BoolVar(&cfg.KeepDatabases, "keep-databases", false, "keep benchmark databases after each run")
	flag.BoolVar(&cfg.SkipDiagnostics, "skip-diagnostics", false, "skip rewrite_only and per-partition medium diagnostics")
	flag.Parse()

	workDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cfg.WorkDir = workDir
	cfg.TempDir = tempDir

	sizeMap := map[string]sizeSpec{
		"small":  {Name: "small", DirtyDomains: 20_480},
		"medium": {Name: "medium", DirtyDomains: 204_800},
		"large":  {Name: "large", DirtyDomains: 1_024_000},
	}
	for _, name := range strings.Split(sizeFlag, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		spec, ok := sizeMap[name]
		if !ok {
			return nil, fmt.Errorf("unknown size %q", name)
		}
		cfg.Sizes = append(cfg.Sizes, spec)
	}
	if len(cfg.Sizes) == 0 {
		return nil, errors.New("no benchmark sizes selected")
	}
	if cfg.WarmupPairs < 0 || cfg.MeasuredPairs <= 0 || cfg.MediumDiagRuns < 0 {
		return nil, errors.New("run counts must be non-negative, with measured-pairs > 0")
	}
	switch cfg.PartitionSkew {
	case "no", "little", "large":
	default:
		return nil, fmt.Errorf("invalid -partition-skew %q: expected one of no,little,large", cfg.PartitionSkew)
	}
	if cfg.Balance < 0 || cfg.Balance > 75 {
		return nil, errors.New("invalid -balance: expected an integer percentage between 0 and 75")
	}
	if cfg.CoalesceWorkers <= 0 {
		return nil, errors.New("invalid -coalesce-workers: expected a positive integer")
	}
	if cfg.CoalesceWorkers > partitionCount {
		cfg.CoalesceWorkers = partitionCount
	}
	return cfg, nil
}

func buildFixture(cfg *config, root string, size sizeSpec) (*fixture, error) {
	dir := filepath.Join(root, fixtureDirName(size.Name, cfg.PartitionSkew, cfg.Balance))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	fx := &fixture{
		SizeName:      size.Name,
		DirtyDomains:  size.DirtyDomains,
		PartitionSkew: cfg.PartitionSkew,
		Balance:       cfg.Balance,
		Files: fixtureFiles{
			Domains:        filepath.Join(dir, "domains.csv"),
			Certs:          filepath.Join(dir, "certs.csv"),
			DomainCerts:    filepath.Join(dir, "domain_certs.csv"),
			Policies:       filepath.Join(dir, "policies.csv"),
			DomainPolicies: filepath.Join(dir, "domain_policies.csv"),
			DomainPayloads: filepath.Join(dir, "domain_payloads.csv"),
			Dirty:          filepath.Join(dir, "dirty.csv"),
		},
	}

	staleCount := size.DirtyDomains * 5 / 1000
	activeCount := size.DirtyDomains - staleCount
	mixedCount := mixedDomainsForBalance(activeCount, cfg.Balance)
	certOnlyCount := activeCount - mixedCount
	fx.StaleDomains = staleCount
	fx.MixedDomains = mixedCount
	fx.CertOnlyDomains = certOnlyCount
	fx.ActiveDomains = activeCount
	fx.ExpectedPayloadRows = activeCount
	fx.ExpectedDomainRowsNew = activeCount

	// The partition-skew flag controls how much active work lands in each partition.
	totalPerPartition := distributeBySkew(size.DirtyDomains, cfg.PartitionSkew)
	certOnlyPerPartition := allocatePerPartition(totalPerPartition, certOnlyCount)
	mixedPerPartition := allocatePerPartition(totalPerPartition, mixedCount)
	stalePerPartition := make([]int, partitionCount)
	for partition := 0; partition < partitionCount; partition++ {
		stalePerPartition[partition] = totalPerPartition[partition] - certOnlyPerPartition[partition] - mixedPerPartition[partition]
		fx.PartitionStats[partition] = partitionFixtureStats{
			DirtyDomains:    totalPerPartition[partition],
			ActiveDomains:   certOnlyPerPartition[partition] + mixedPerPartition[partition],
			StaleDomains:    stalePerPartition[partition],
			CertOnlyDomains: certOnlyPerPartition[partition],
			MixedDomains:    mixedPerPartition[partition],
		}
	}

	const expiration = "2035-01-01 00:00:00"
	const certPayloadBase64 = "Y2VydC1wYXlsb2Fk"
	const policyPayloadBase64 = "cG9saWN5LXBheWxvYWQ="
	stalePayload := bytes.Repeat([]byte{0x55}, common.SHA256Size)
	stalePayloadID := sha256.Sum256(stalePayload)
	stalePayloadBase64 := base64.StdEncoding.EncodeToString(stalePayload)
	stalePayloadIDBase64 := base64.StdEncoding.EncodeToString(stalePayloadID[:])

	domainWriter, err := newCSVWriter(fx.Files.Domains)
	if err != nil {
		return nil, err
	}
	defer domainWriter.Close()
	certWriter, err := newCSVWriter(fx.Files.Certs)
	if err != nil {
		return nil, err
	}
	defer certWriter.Close()
	domainCertWriter, err := newCSVWriter(fx.Files.DomainCerts)
	if err != nil {
		return nil, err
	}
	defer domainCertWriter.Close()
	policyWriter, err := newCSVWriter(fx.Files.Policies)
	if err != nil {
		return nil, err
	}
	defer policyWriter.Close()
	domainPolicyWriter, err := newCSVWriter(fx.Files.DomainPolicies)
	if err != nil {
		return nil, err
	}
	defer domainPolicyWriter.Close()
	domainPayloadWriter, err := newCSVWriter(fx.Files.DomainPayloads)
	if err != nil {
		return nil, err
	}
	defer domainPayloadWriter.Close()
	dirtyWriter, err := newCSVWriter(fx.Files.Dirty)
	if err != nil {
		return nil, err
	}
	defer dirtyWriter.Close()

	fx.ExpectedRows = make([]expectedPayloadRow, 0, fx.ActiveDomains)

	var certSeed uint64 = 1
	var policySeed uint64 = 1
	var globalDomainOrdinal uint64

	for partition := 0; partition < partitionCount; partition++ {
		// Cert-only domains dominate the fixture, matching the intended real-world skew.
		for i := 0; i < certOnlyPerPartition[partition]; i++ {
			domainID := makeDomainID(partition, globalDomainOrdinal)
			name := domainName(certOnlyNamePrefix, partition, i)
			if err := writeActiveDomain(domainWriter, dirtyWriter, certWriter, domainCertWriter,
				domainID, name, &certSeed, expiration, certPayloadBase64); err != nil {
				return nil, err
			}
			expectation := buildCertExpectation(domainID, certSeed-4)
			fx.ExpectedRows = append(fx.ExpectedRows, expectation)
			globalDomainOrdinal++
		}
		// Mixed domains reuse the same cert-chain shape but also exercise the policy-side
		// recursive closure and aggregation.
		for i := 0; i < mixedPerPartition[partition]; i++ {
			domainID := makeDomainID(partition, globalDomainOrdinal)
			name := domainName(mixedNamePrefix, partition, i)
			if err := writeActiveDomain(domainWriter, dirtyWriter, certWriter, domainCertWriter,
				domainID, name, &certSeed, expiration, certPayloadBase64); err != nil {
				return nil, err
			}
			expectation := buildMixedExpectation(domainID, certSeed-4, policySeed)
			fx.ExpectedRows = append(fx.ExpectedRows, expectation)
			for _, row := range buildPolicyRows(domainID, policySeed, expiration, policyPayloadBase64) {
				if err := policyWriter.Write(row...); err != nil {
					return nil, err
				}
			}
			for _, row := range buildDomainPolicyRows(domainID, policySeed+2) {
				if err := domainPolicyWriter.Write(row...); err != nil {
					return nil, err
				}
			}
			policySeed += 3
			globalDomainOrdinal++
		}
		// Stale domains start with preexisting rows but no remaining cert/policy links so the
		// cleanup logic has concrete work to do.
		for i := 0; i < stalePerPartition[partition]; i++ {
			domainID := makeDomainID(partition, globalDomainOrdinal)
			name := domainName(staleNamePrefix, partition, i)
			if err := domainWriter.Write(base64ID(domainID), name); err != nil {
				return nil, err
			}
			if err := dirtyWriter.Write(base64ID(domainID)); err != nil {
				return nil, err
			}
			if err := domainPayloadWriter.Write(
				base64ID(domainID),
				stalePayloadBase64,
				stalePayloadIDBase64,
				"",
				"",
			); err != nil {
				return nil, err
			}
			globalDomainOrdinal++
		}
	}

	sort.Slice(fx.ExpectedRows, func(i, j int) bool {
		return bytes.Compare(fx.ExpectedRows[i].DomainID[:], fx.ExpectedRows[j].DomainID[:]) < 0
	})

	return fx, nil
}

func runWarmups(cfg *config, fx *fixture) error {
	for pair := 0; pair < cfg.WarmupPairs; pair++ {
		order := pairOrder(pair)
		for idx, variant := range order {
			label := fmt.Sprintf("warmup-pair-%02d-step-%d", pair+1, idx+1)
			if _, err := runFullSample(cfg, fx, variant, label, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func runMeasuredPairs(cfg *config, fx *fixture) ([]runResult, error) {
	results := make([]runResult, 0, cfg.MeasuredPairs*2)
	for pair := 0; pair < cfg.MeasuredPairs; pair++ {
		order := pairOrder(pair)
		for idx, variant := range order {
			label := fmt.Sprintf("pair-%02d-step-%d", pair+1, idx+1)
			result, err := runFullSample(cfg, fx, variant, label, true)
			if err != nil {
				return nil, err
			}
			results = append(results, result)
		}
	}
	return results, nil
}

func runMediumDiagnostics(cfg *config, fx *fixture) ([]runResult, error) {
	var results []runResult
	for i := 0; i < cfg.MediumDiagRuns; i++ {
		label := fmt.Sprintf("rewrite-full-%02d", i+1)
		result, err := runFullSample(cfg, fx, rewriteVariant, label, true)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}

	for partition := 0; partition < partitionCount; partition++ {
		label := fmt.Sprintf("partition-%02d", partition)
		result, err := runPartitionDiagnostic(cfg, fx, partition, label)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func runFullSample(cfg *config, fx *fixture, v variant, runLabel string, record bool) (runResult, error) {
	dbName := benchmarkDBName(v.Name, fx.SizeName, fx.PartitionSkew, fx.Balance, runLabel)
	if err := createBenchmarkDB(dbName); err != nil {
		return runResult{}, err
	}
	created := true
	if !cfg.KeepDatabases {
		defer func() {
			if created {
				_ = dropBenchmarkDB(dbName)
			}
		}()
	}

	conn, err := connectBenchmarkDB(dbName)
	if err != nil {
		return runResult{}, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), fullRunTimeout)
	defer cancel()

	if err := installProcedure(ctx, conn.DB(), v); err != nil {
		return runResult{}, err
	}
	if err := loadFixture(ctx, conn.DB(), fx.Files); err != nil {
		return runResult{}, err
	}
	if err := verifyFixtureCounts(ctx, conn.DB(), fx); err != nil {
		return runResult{}, err
	}

	// Reopen the connection for the measured step so setup work and measured work do not share
	// the same session state unnecessarily.
	measuredConn, err := connectBenchmarkDB(dbName)
	if err != nil {
		return runResult{}, err
	}
	defer measuredConn.Close()

	start := time.Now()
	if err := runCoalescingWithWorkers(ctx, measuredConn.DB(), v, cfg.CoalesceWorkers); err != nil {
		return runResult{}, err
	}
	elapsed := time.Since(start)

	result, err := collectAndValidateFullRun(ctx, measuredConn.DB(), fx, v, runLabel, elapsed)
	if err != nil {
		return runResult{}, err
	}

	if record {
		fmt.Printf("%s/%s %s: %s (dirty/s %.0f, active/s %.0f)\n",
			fx.SizeName, v.Name, runLabel, result.Elapsed.Round(time.Millisecond),
			result.DirtyPerSecond, result.ActivePerSecond)
	}

	if cfg.KeepDatabases {
		created = false
	}
	return result, nil
}

func runPartitionDiagnostic(cfg *config, fx *fixture, partition int, runLabel string) (runResult, error) {
	dbName := benchmarkDBName(newVariant.Name, fx.SizeName, fx.PartitionSkew, fx.Balance, runLabel)
	if err := createBenchmarkDB(dbName); err != nil {
		return runResult{}, err
	}
	created := true
	if !cfg.KeepDatabases {
		defer func() {
			if created {
				_ = dropBenchmarkDB(dbName)
			}
		}()
	}

	conn, err := connectBenchmarkDB(dbName)
	if err != nil {
		return runResult{}, err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), partitionRunTimeout)
	defer cancel()

	if err := installProcedure(ctx, conn.DB(), newVariant); err != nil {
		return runResult{}, err
	}
	if err := loadFixture(ctx, conn.DB(), fx.Files); err != nil {
		return runResult{}, err
	}
	if err := verifyFixtureCounts(ctx, conn.DB(), fx); err != nil {
		return runResult{}, err
	}

	start := time.Now()
	if err := callVariantPartition(ctx, conn.DB(), newVariant, partition); err != nil {
		return runResult{}, err
	}
	elapsed := time.Since(start)

	result, err := collectPartitionDiagnostic(ctx, conn.DB(), fx, partition, runLabel, elapsed)
	if err != nil {
		return runResult{}, err
	}
	fmt.Printf("medium/new %s: %s (%d dirty domains in partition)\n",
		runLabel, result.Elapsed.Round(time.Millisecond), fx.PartitionStats[partition].DirtyDomains)

	if cfg.KeepDatabases {
		created = false
	}
	return result, nil
}

func pairOrder(pairIndex int) []variant {
	if pairIndex%2 == 0 {
		return []variant{oldVariant, newVariant}
	}
	return []variant{newVariant, oldVariant}
}

func benchmarkDBName(variantName, sizeName, partitionSkew string, balance int, label string) string {
	return fmt.Sprintf(
		"bench_coalesce_%s_%s_s%s_b%d_%08x",
		shortVariantName(variantName),
		sizeName,
		shortPartitionSkew(partitionSkew),
		balance,
		crc32.ChecksumIEEE([]byte(label)),
	)
}

func fixtureDirName(sizeName, partitionSkew string, balance int) string {
	replacer := strings.NewReplacer("-", "_", ".", "_")
	return fmt.Sprintf("%s_skew_%s_balance_%d", sizeName, replacer.Replace(partitionSkew), balance)
}

func prepareRunTempDir(root string) (string, error) {
	return os.MkdirTemp(root, "run-")
}

func shortVariantName(name string) string {
	switch name {
	case "old":
		return "old"
	case "new":
		return "new"
	case "rewrite_only":
		return "rwo"
	default:
		return "unk"
	}
}

func shortPartitionSkew(skew string) string {
	switch skew {
	case "no":
		return "n"
	case "little":
		return "l"
	case "large":
		return "g"
	default:
		return "u"
	}
}

func createBenchmarkDB(dbName string) error {
	script := tools.CreateSchemaScript()
	cmd := exec.Command("bash")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, script); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, "create_new_db "+dbName+"\n"); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("create db %s: %w\n%s", dbName, err, output.String())
	}
	return nil
}

func dropBenchmarkDB(dbName string) error {
	conn, err := sql.Open("mysql", benchmarkAdminDSN())
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+dbName)
	return err
}

func connectBenchmarkDB(dbName string) (db.Conn, error) {
	cfg := db.NewConfig(
		mysql.WithDefaults(),
		mysql.WithLocalSocket("/var/run/mysqld/mysqld.sock"),
		mysql.WithEnvironment(),
		db.WithDB(dbName),
	)
	return mysql.Connect(cfg)
}

func benchmarkAdminDSN() string {
	user := os.Getenv("MYSQL_USER")
	if user == "" {
		user = "root"
	}
	pass := os.Getenv("MYSQL_PASSWORD")
	host := os.Getenv("MYSQL_HOST")
	port := os.Getenv("MYSQL_PORT")
	if host == "" && port == "" {
		return fmt.Sprintf("%s:%s@unix(/var/run/mysqld/mysqld.sock)/mysql?parseTime=true&multiStatements=true", user, passPrefix(pass))
	}
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "3306"
	}
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/mysql?parseTime=true&multiStatements=true", user, passPrefix(pass), host, port)
}

func passPrefix(pass string) string {
	if pass == "" {
		return ""
	}
	return pass
}

func installProcedure(ctx context.Context, db *sql.DB, v variant) error {
	if _, err := db.ExecContext(ctx, "DROP PROCEDURE IF EXISTS calc_dirty_domains"); err != nil {
		return err
	}
	body, err := procedureFiles.ReadFile(filepath.Join("testdata", v.ProcedurePath))
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, string(body))
	return err
}

func loadFixture(ctx context.Context, db *sql.DB, files fixtureFiles) error {
	// CSV replay keeps every sample byte-for-byte identical while still loading quickly enough
	// for large fixtures.
	loaders := []struct {
		path  string
		query string
	}{
		{
			path: files.Domains,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE domains
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@domain_id,@domain_name) SET
domain_id = FROM_BASE64(@domain_id),
domain_name = @domain_name`,
		},
		{
			path: files.Certs,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE certs
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@cert_id,@expiration,@parent_id,@payload) SET
cert_id = FROM_BASE64(@cert_id),
expiration = @expiration,
parent_id = FROM_BASE64(NULLIF(@parent_id,'')),
payload = FROM_BASE64(@payload)`,
		},
		{
			path: files.DomainCerts,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE domain_certs
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@domain_id,@cert_id) SET
domain_id = FROM_BASE64(@domain_id),
cert_id = FROM_BASE64(@cert_id)`,
		},
		{
			path: files.Policies,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE policies
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@policy_id,@expiration,@parent_id,@payload) SET
policy_id = FROM_BASE64(@policy_id),
expiration = @expiration,
parent_id = FROM_BASE64(NULLIF(@parent_id,'')),
payload = FROM_BASE64(@payload)`,
		},
		{
			path: files.DomainPolicies,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE domain_policies
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@domain_id,@policy_id) SET
domain_id = FROM_BASE64(@domain_id),
policy_id = FROM_BASE64(@policy_id)`,
		},
		{
			path: files.DomainPayloads,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE domain_payloads
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@domain_id,@cert_ids,@cert_ids_id,@policy_ids,@policy_ids_id) SET
domain_id = FROM_BASE64(@domain_id),
cert_ids = FROM_BASE64(NULLIF(@cert_ids,'')),
cert_ids_id = FROM_BASE64(NULLIF(@cert_ids_id,'')),
policy_ids = FROM_BASE64(NULLIF(@policy_ids,'')),
policy_ids_id = FROM_BASE64(NULLIF(@policy_ids_id,''))`,
		},
		{
			path: files.Dirty,
			query: `LOAD DATA CONCURRENT INFILE ? IGNORE INTO TABLE dirty
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n'
(@domain_id) SET
domain_id = FROM_BASE64(@domain_id)`,
		},
	}

	secureDir, err := mysqlSecureFilePriv(ctx, db)
	if err != nil {
		return err
	}
	stagedFiles := make([]string, 0, len(loaders))
	if secureDir != "" {
		defer func() {
			for _, path := range stagedFiles {
				_ = os.Remove(path)
			}
		}()
	}

	for _, loader := range loaders {
		loadPath := loader.path
		if secureDir != "" {
			loadPath, err = copyIntoDir(loader.path, secureDir)
			if err != nil {
				return fmt.Errorf("stage %s into secure-file-priv dir: %w", filepath.Base(loader.path), err)
			}
			stagedFiles = append(stagedFiles, loadPath)
		}
		if err := os.Chmod(loadPath, 0o644); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, loader.query, loadPath); err != nil {
			return fmt.Errorf("load %s: %w", filepath.Base(loader.path), err)
		}
	}
	return nil
}

func mysqlSecureFilePriv(ctx context.Context, db *sql.DB) (string, error) {
	var secureDir sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT @@GLOBAL.secure_file_priv").Scan(&secureDir); err != nil {
		return "", fmt.Errorf("query @@GLOBAL.secure_file_priv: %w", err)
	}
	if !secureDir.Valid {
		return "", nil
	}
	dir := strings.TrimSpace(secureDir.String)
	if dir == "" || strings.EqualFold(dir, "NULL") {
		return "", nil
	}
	return filepath.Clean(dir), nil
}

func copyIntoDir(srcPath, dstDir string) (string, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}

	dst, err := os.CreateTemp(dstDir, "bench-coalesce-*.csv")
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}
	if err := dst.Sync(); err != nil {
		return "", err
	}
	return dst.Name(), nil
}

func verifyFixtureCounts(ctx context.Context, db *sql.DB, fx *fixture) error {
	checks := []struct {
		query string
		want  int
		name  string
	}{
		{"SELECT COUNT(*) FROM dirty", fx.DirtyDomains, "dirty"},
		{"SELECT COUNT(*) FROM domains", fx.DirtyDomains, "domains"},
		{"SELECT COUNT(*) FROM domain_payloads", fx.StaleDomains, "domain_payloads"},
		{"SELECT COUNT(*) FROM certs", fx.CertOnlyDomains*4 + fx.MixedDomains*4, "certs"},
		{"SELECT COUNT(*) FROM domain_certs", fx.CertOnlyDomains*2 + fx.MixedDomains*2, "domain_certs"},
		{"SELECT COUNT(*) FROM policies", fx.MixedDomains * 3, "policies"},
		{"SELECT COUNT(*) FROM domain_policies", fx.MixedDomains, "domain_policies"},
	}
	for _, check := range checks {
		got, err := countQuery(ctx, db, check.query)
		if err != nil {
			return err
		}
		if got != check.want {
			return fmt.Errorf("fixture count mismatch for %s: got %d want %d", check.name, got, check.want)
		}
	}
	return nil
}

func collectAndValidateFullRun(
	ctx context.Context,
	db *sql.DB,
	fx *fixture,
	v variant,
	runLabel string,
	elapsed time.Duration,
) (runResult, error) {
	if err := validateActivePayloads(ctx, db, fx); err != nil {
		return runResult{}, fmt.Errorf("validate active payloads: %w", err)
	}

	payloadRows, err := countQuery(ctx, db, "SELECT COUNT(*) FROM domain_payloads")
	if err != nil {
		return runResult{}, err
	}
	domainRows, err := countQuery(ctx, db, "SELECT COUNT(*) FROM domains")
	if err != nil {
		return runResult{}, err
	}
	remainingStalePayloads, err := countQuery(ctx, db, `
SELECT COUNT(*)
FROM domain_payloads AS dp
INNER JOIN domains AS d ON d.domain_id = dp.domain_id
WHERE d.domain_name LIKE 'stale-%'`)
	if err != nil {
		return runResult{}, err
	}
	remainingStaleDomains, err := countQuery(ctx, db, "SELECT COUNT(*) FROM domains WHERE domain_name LIKE 'stale-%'")
	if err != nil {
		return runResult{}, err
	}

	expectedPayloadRows := fx.ExpectedPayloadRows
	if !v.ExpectStaleGone {
		expectedPayloadRows += fx.StaleDomains
	}
	if payloadRows != expectedPayloadRows {
		return runResult{}, fmt.Errorf("payload row count mismatch: got %d want %d", payloadRows, expectedPayloadRows)
	}
	expectedDomainRows := fx.DirtyDomains
	if !v.ExpectDomainRows {
		expectedDomainRows = fx.ExpectedDomainRowsNew
	}
	if domainRows != expectedDomainRows {
		return runResult{}, fmt.Errorf("domain row count mismatch: got %d want %d", domainRows, expectedDomainRows)
	}

	expectedRemainingStalePayloads := fx.StaleDomains
	if v.ExpectStaleGone {
		expectedRemainingStalePayloads = 0
	}
	if remainingStalePayloads != expectedRemainingStalePayloads {
		return runResult{}, fmt.Errorf("remaining stale payload rows mismatch: got %d want %d", remainingStalePayloads, expectedRemainingStalePayloads)
	}
	expectedRemainingStaleDomains := fx.StaleDomains
	if !v.ExpectDomainRows {
		expectedRemainingStaleDomains = 0
	}
	if remainingStaleDomains != expectedRemainingStaleDomains {
		return runResult{}, fmt.Errorf("remaining stale domain rows mismatch: got %d want %d", remainingStaleDomains, expectedRemainingStaleDomains)
	}

	return runResult{
		Variant:                 v.Name,
		SizeName:                fx.SizeName,
		RunLabel:                runLabel,
		Elapsed:                 elapsed,
		DirtyPerSecond:          float64(fx.DirtyDomains) / elapsed.Seconds(),
		ActivePerSecond:         float64(fx.ActiveDomains) / elapsed.Seconds(),
		DomainPayloadRows:       payloadRows,
		DomainRows:              domainRows,
		RemovedStalePayloadRows: fx.StaleDomains - remainingStalePayloads,
		RemovedStaleDomainRows:  fx.StaleDomains - remainingStaleDomains,
	}, nil
}

func collectPartitionDiagnostic(
	ctx context.Context,
	db *sql.DB,
	fx *fixture,
	partition int,
	runLabel string,
	elapsed time.Duration,
) (runResult, error) {
	stats := fx.PartitionStats[partition]
	payloadRows, err := countQuery(ctx, db, fmt.Sprintf("SELECT COUNT(*) FROM domain_payloads PARTITION(p%d)", partition))
	if err != nil {
		return runResult{}, err
	}
	domainRows, err := countQuery(ctx, db, fmt.Sprintf("SELECT COUNT(*) FROM domains PARTITION(p%d)", partition))
	if err != nil {
		return runResult{}, err
	}
	remainingStalePayloads, err := countQuery(ctx, db, fmt.Sprintf(`
SELECT COUNT(*)
FROM domain_payloads PARTITION(p%d) AS dp
INNER JOIN domains PARTITION(p%d) AS d ON d.domain_id = dp.domain_id
WHERE d.domain_name LIKE 'stale-%%'`, partition, partition))
	if err != nil {
		return runResult{}, err
	}
	remainingStaleDomains, err := countQuery(ctx, db, fmt.Sprintf(
		"SELECT COUNT(*) FROM domains PARTITION(p%d) WHERE domain_name LIKE 'stale-%%'", partition))
	if err != nil {
		return runResult{}, err
	}

	if payloadRows != stats.ActiveDomains {
		return runResult{}, fmt.Errorf("partition %d payload rows mismatch: got %d want %d", partition, payloadRows, stats.ActiveDomains)
	}
	if domainRows != stats.ActiveDomains {
		return runResult{}, fmt.Errorf("partition %d domain rows mismatch: got %d want %d", partition, domainRows, stats.ActiveDomains)
	}
	if remainingStalePayloads != 0 || remainingStaleDomains != 0 {
		return runResult{}, fmt.Errorf("partition %d stale rows remain payloads=%d domains=%d", partition, remainingStalePayloads, remainingStaleDomains)
	}

	return runResult{
		Variant:                 newVariant.Name,
		SizeName:                fx.SizeName,
		RunLabel:                runLabel,
		Partition:               &partition,
		Elapsed:                 elapsed,
		DirtyPerSecond:          safeRate(stats.DirtyDomains, elapsed),
		ActivePerSecond:         safeRate(stats.ActiveDomains, elapsed),
		DomainPayloadRows:       payloadRows,
		DomainRows:              domainRows,
		RemovedStalePayloadRows: stats.StaleDomains,
		RemovedStaleDomainRows:  stats.StaleDomains,
	}, nil
}

func validateActivePayloads(ctx context.Context, db *sql.DB, fx *fixture) error {
	// Compare only the active domains here. Stale rows are variant-dependent by design.
	rows, err := db.QueryContext(ctx, `
SELECT d.domain_id, dp.cert_ids_id, OCTET_LENGTH(dp.cert_ids), dp.policy_ids_id, OCTET_LENGTH(dp.policy_ids)
FROM domain_payloads AS dp
INNER JOIN domains AS d ON d.domain_id = dp.domain_id
WHERE d.domain_name NOT LIKE 'stale-%'
ORDER BY d.domain_id`)
	if err != nil {
		return err
	}
	defer rows.Close()

	idx := 0
	for rows.Next() {
		if idx >= len(fx.ExpectedRows) {
			return fmt.Errorf("received more active rows than expected")
		}
		var (
			domainID    []byte
			certIDsID   []byte
			certLen     sql.NullInt64
			policyIDsID []byte
			policyLen   sql.NullInt64
		)
		if err := rows.Scan(&domainID, &certIDsID, &certLen, &policyIDsID, &policyLen); err != nil {
			return err
		}
		var gotDomain common.SHA256Output
		copy(gotDomain[:], domainID)
		expect := fx.ExpectedRows[idx]
		if gotDomain != expect.DomainID {
			return fmt.Errorf("domain mismatch at row %d", idx)
		}
		if err := compareOptionalID("cert_ids_id", certIDsID, expect.CertIDsID); err != nil {
			return fmt.Errorf("domain %x: %w", gotDomain[:4], err)
		}
		if got := int(nullIntValue(certLen)); got != expect.CertLen {
			return fmt.Errorf("domain %x cert length mismatch: got %d want %d", gotDomain[:4], got, expect.CertLen)
		}
		if err := compareOptionalID("policy_ids_id", policyIDsID, expect.PolicyIDsID); err != nil {
			return fmt.Errorf("domain %x: %w", gotDomain[:4], err)
		}
		if got := int(nullIntValue(policyLen)); got != expect.PolicyLen {
			return fmt.Errorf("domain %x policy length mismatch: got %d want %d", gotDomain[:4], got, expect.PolicyLen)
		}
		idx++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if idx != len(fx.ExpectedRows) {
		return fmt.Errorf("active rows mismatch: got %d want %d", idx, len(fx.ExpectedRows))
	}
	return nil
}

func compareOptionalID(field string, got []byte, want *common.SHA256Output) error {
	if want == nil {
		if got != nil {
			return fmt.Errorf("%s mismatch: expected NULL", field)
		}
		return nil
	}
	if got == nil {
		return fmt.Errorf("%s mismatch: expected value", field)
	}
	if !bytes.Equal(got, want[:]) {
		return fmt.Errorf("%s mismatch", field)
	}
	return nil
}

func nullIntValue(v sql.NullInt64) int64 {
	if !v.Valid {
		return 0
	}
	return v.Int64
}

func countQuery(ctx context.Context, db *sql.DB, query string) (int, error) {
	var count int
	err := db.QueryRowContext(ctx, query).Scan(&count)
	return count, err
}

func safeRate(count int, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(count) / elapsed.Seconds()
}

func printFullSummary(results []runResult, cfg *config, fixtures map[string]*fixture) {
	summaries := summarizeFullRuns(results)
	fmt.Printf("\n== Full-run summary ==\n")
	printWorkloadSummary(cfg, fixtures)
	fmt.Printf("%-8s %-14s %-12s %-12s %-12s %-12s\n", "size", "variant", "median", "IQR", "dirty/s", "active/s")
	for _, size := range cfg.Sizes {
		for _, v := range headlineVariants {
			summary := summaries[size.Name+"/"+v.Name]
			fmt.Printf("%-8s %-14s %-12s %-12s %-12.0f %-12.0f\n",
				size.Name, v.Name,
				summary.Median.Round(time.Millisecond),
				summary.IQR.Round(time.Millisecond),
				summary.MedianDirty,
				summary.MedianActive)
		}
	}

	fmt.Printf("\n%-8s %-12s %-12s %-14s\n", "size", "old", "new", "new vs old")
	for _, delta := range buildPairDeltas(summaries, cfg.Sizes) {
		fmt.Printf("%-8s %-12s %-12s %8.2f%%\n",
			delta.SizeName,
			delta.OldMedian.Round(time.Millisecond),
			delta.NewMedian.Round(time.Millisecond),
			delta.PercentFaster)
	}

	if cfg.Balance == 0 {
		fmt.Printf("\nnote: this run is cert-only (-balance 0), so policy aggregation is absent.\n")
		fmt.Printf("the new procedure may look slower here because fixed cleanup/update overhead is still present while the old procedure avoids policy-side work entirely.\n")
	}
}

func printWorkloadSummary(cfg *config, fixtures map[string]*fixture) {
	fmt.Printf("workload: partition-skew=%s, balance=%d%%, coalesce-workers=%d\n", cfg.PartitionSkew, cfg.Balance, cfg.CoalesceWorkers)
	fmt.Printf("%-8s %-10s %-10s %-10s %-10s\n", "size", "active", "cert-only", "mixed", "stale")
	for _, size := range cfg.Sizes {
		fx := fixtures[size.Name]
		fmt.Printf("%-8s %-10d %-10d %-10d %-10d\n",
			size.Name,
			fx.ActiveDomains,
			fx.CertOnlyDomains,
			fx.MixedDomains,
			fx.StaleDomains,
		)
	}
	fmt.Println()
}

func printDiagnosticSummary(results []runResult) {
	var fullRewrite []runResult
	var partitions []runResult
	for _, result := range results {
		if result.Partition == nil {
			fullRewrite = append(fullRewrite, result)
			continue
		}
		partitions = append(partitions, result)
	}
	if len(fullRewrite) > 0 {
		elapsed := make([]time.Duration, len(fullRewrite))
		for i, result := range fullRewrite {
			elapsed[i] = result.Elapsed
		}
		fmt.Printf("rewrite_only full runs: median=%s iqr=%s\n",
			medianDuration(elapsed).Round(time.Millisecond),
			iqrDuration(elapsed).Round(time.Millisecond))
	}

	sort.Slice(partitions, func(i, j int) bool {
		return *partitions[i].Partition < *partitions[j].Partition
	})
	fmt.Printf("\n%-10s %-12s %-12s %-12s\n", "partition", "elapsed", "dirty", "active")
	elapsed := make([]time.Duration, 0, len(partitions))
	for _, result := range partitions {
		elapsed = append(elapsed, result.Elapsed)
		fmt.Printf("p%-9d %-12s %-12.0f %-12.0f\n",
			*result.Partition,
			result.Elapsed.Round(time.Millisecond),
			result.DirtyPerSecond,
			result.ActivePerSecond)
	}
	if len(elapsed) > 0 {
		sort.Slice(elapsed, func(i, j int) bool { return elapsed[i] < elapsed[j] })
		fmt.Printf("\npartition elapsed summary: min=%s p50=%s p95=%s max=%s\n",
			elapsed[0].Round(time.Millisecond),
			percentileDuration(elapsed, 0.50).Round(time.Millisecond),
			percentileDuration(elapsed, 0.95).Round(time.Millisecond),
			elapsed[len(elapsed)-1].Round(time.Millisecond))
	}
}

func summarizeFullRuns(results []runResult) map[string]sizeRunSummary {
	grouped := map[string][]runResult{}
	for _, result := range results {
		if result.Partition != nil {
			continue
		}
		key := result.SizeName + "/" + result.Variant
		grouped[key] = append(grouped[key], result)
	}

	summaries := make(map[string]sizeRunSummary, len(grouped))
	for key, groupedResults := range grouped {
		elapsed := make([]time.Duration, len(groupedResults))
		dirtyRates := make([]float64, len(groupedResults))
		activeRates := make([]float64, len(groupedResults))
		for i, result := range groupedResults {
			elapsed[i] = result.Elapsed
			dirtyRates[i] = result.DirtyPerSecond
			activeRates[i] = result.ActivePerSecond
		}
		summaries[key] = sizeRunSummary{
			Variant:      groupedResults[0].Variant,
			SizeName:     groupedResults[0].SizeName,
			Samples:      groupedResults,
			Median:       medianDuration(elapsed),
			IQR:          iqrDuration(elapsed),
			MedianDirty:  medianFloat64(dirtyRates),
			MedianActive: medianFloat64(activeRates),
		}
	}
	return summaries
}

func buildPairDeltas(summaries map[string]sizeRunSummary, sizes []sizeSpec) []pairDelta {
	deltas := make([]pairDelta, 0, len(sizes))
	for _, size := range sizes {
		oldSummary := summaries[size.Name+"/old"]
		newSummary := summaries[size.Name+"/new"]
		if oldSummary.Median == 0 || newSummary.Median == 0 {
			continue
		}
		deltas = append(deltas, pairDelta{
			SizeName:      size.Name,
			OldMedian:     oldSummary.Median,
			NewMedian:     newSummary.Median,
			PercentFaster: (float64(oldSummary.Median-newSummary.Median) / float64(oldSummary.Median)) * 100,
		})
	}
	return deltas
}

func medianDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return percentileDuration(sorted, 0.50)
}

func iqrDuration(values []time.Duration) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	q1 := percentileDuration(sorted, 0.25)
	q3 := percentileDuration(sorted, 0.75)
	return q3 - q1
}

func percentileDuration(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	index := int(math.Round(p * float64(len(sorted)-1)))
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func medianFloat64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	index := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[index]
	}
	return (sorted[index-1] + sorted[index]) / 2
}

func distributeBySkew(total int, skew string) []int {
	weights := make([]float64, partitionCount)
	for i := 0; i < partitionCount; i++ {
		weights[i] = 1.0
	}

	switch skew {
	case "no":
		// All partitions use the same weight, so only integer rounding creates tiny differences.
	case "little":
		// Two deterministic partitions get 10% less work than the rest.
		weights[partitionCount-2] = 0.9
		weights[partitionCount-1] = 0.9
	case "large":
		// The upper half of the partitions get 25% less work than the lower half.
		for i := partitionCount / 2; i < partitionCount; i++ {
			weights[i] = 0.75
		}
	default:
		panic("unsupported skew")
	}
	return largestRemainder(total, weights)
}

func mixedDomainsForBalance(activeDomains, balance int) int {
	if activeDomains == 0 || balance == 0 {
		return 0
	}
	// Each active domain always contributes 4 certificate IDs. A mixed domain additionally
	// contributes 3 policy IDs, so the maximum achievable policy/certificate ratio is 75%.
	mixed := int(math.Round(float64(activeDomains*4*balance) / 300.0))
	if mixed > activeDomains {
		return activeDomains
	}
	return mixed
}

type partitionCaller interface {
	callPartition(context.Context, int) error
}

type sqlPartitionCaller struct {
	db      *sql.DB
	variant variant
}

func (c sqlPartitionCaller) callPartition(ctx context.Context, partition int) error {
	return callVariantPartition(ctx, c.db, c.variant, partition)
}

func runCoalescingWithWorkers(ctx context.Context, db *sql.DB, v variant, workers int) error {
	return callPartitionsWithWorkers(ctx, sqlPartitionCaller{db: db, variant: v}, workers)
}

func callVariantPartition(ctx context.Context, db *sql.DB, v variant, partition int) error {
	if !v.Chunked {
		_, err := db.ExecContext(ctx, "CALL calc_dirty_domains(?)", partition)
		return err
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	for {
		var processedRows int64
		if _, err := conn.ExecContext(
			ctx,
			"CALL calc_dirty_domains(?, ?, @processed_rows)",
			partition,
			v.ChunkSize,
		); err != nil {
			return err
		}
		if err := conn.QueryRowContext(ctx, "SELECT @processed_rows").Scan(&processedRows); err != nil {
			return err
		}
		if processedRows == 0 {
			return nil
		}
	}
}

func callPartitionsWithWorkers(ctx context.Context, caller partitionCaller, workers int) error {
	if workers <= 0 {
		return fmt.Errorf("invalid coalescing worker count %d", workers)
	}
	if workers > partitionCount {
		workers = partitionCount
	}

	partitions := make(chan int)
	errs := make([]error, partitionCount)
	wg := sync.WaitGroup{}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for partition := range partitions {
				if err := caller.callPartition(ctx, partition); err != nil {
					errs[partition] = fmt.Errorf(
						"coalescing dirty domains in partition %d: %w",
						partition,
						err,
					)
				}
			}
		}()
	}

	for partition := 0; partition < partitionCount; partition++ {
		partitions <- partition
	}
	close(partitions)
	wg.Wait()

	if err := util.ErrorsCoalesce(errs...); err != nil {
		return fmt.Errorf("coalescing dirty-domain payloads: %w", err)
	}
	return nil
}

func allocatePerPartition(capacity []int, total int) []int {
	weights := make([]float64, len(capacity))
	for i, value := range capacity {
		weights[i] = float64(value)
	}
	allocated := largestRemainder(total, weights)
	for i := range allocated {
		if allocated[i] > capacity[i] {
			panic("allocation exceeded partition capacity")
		}
	}
	return allocated
}

func largestRemainder(total int, weights []float64) []int {
	result := make([]int, len(weights))
	var weightSum float64
	for _, weight := range weights {
		weightSum += weight
	}
	if total == 0 || weightSum == 0 {
		return result
	}

	type remainder struct {
		index int
		value float64
	}
	remainders := make([]remainder, len(weights))
	used := 0
	for i, weight := range weights {
		exact := float64(total) * weight / weightSum
		result[i] = int(math.Floor(exact))
		used += result[i]
		remainders[i] = remainder{index: i, value: exact - float64(result[i])}
	}
	sort.Slice(remainders, func(i, j int) bool {
		if remainders[i].value == remainders[j].value {
			return remainders[i].index < remainders[j].index
		}
		return remainders[i].value > remainders[j].value
	})
	for i := 0; i < total-used; i++ {
		result[remainders[i].index]++
	}
	return result
}

func writeActiveDomain(
	domainWriter, dirtyWriter, certWriter, domainCertWriter *csvWriter,
	domainID common.SHA256Output,
	name string,
	certSeed *uint64,
	expiration string,
	certPayloadBase64 string,
) error {
	if err := domainWriter.Write(base64ID(domainID), name); err != nil {
		return err
	}
	if err := dirtyWriter.Write(base64ID(domainID)); err != nil {
		return err
	}

	rows, leafIDs := buildCertRows(*certSeed, expiration, certPayloadBase64)
	for _, row := range rows {
		if err := certWriter.Write(row...); err != nil {
			return err
		}
	}
	for _, leafID := range leafIDs {
		if err := domainCertWriter.Write(base64ID(domainID), base64ID(leafID)); err != nil {
			return err
		}
	}
	*certSeed += 4

	return nil
}

func buildCertRows(start uint64, expiration, payload string) ([][]string, []common.SHA256Output) {
	root := makeLinearID(0x40, start)
	mid := makeLinearID(0x40, start+1)
	leafA := makeLinearID(0x40, start+2)
	leafB := makeLinearID(0x40, start+3)
	return [][]string{
		{base64ID(root), expiration, "", payload},
		{base64ID(mid), expiration, base64ID(root), payload},
		{base64ID(leafA), expiration, base64ID(mid), payload},
		{base64ID(leafB), expiration, base64ID(root), payload},
	}, []common.SHA256Output{leafA, leafB}
}

func buildPolicyRows(domainID common.SHA256Output, start uint64, expiration, payload string) [][]string {
	_ = domainID
	root := makeLinearID(0x80, start)
	mid := makeLinearID(0x80, start+1)
	leaf := makeLinearID(0x80, start+2)
	return [][]string{
		{base64ID(root), expiration, "", payload},
		{base64ID(mid), expiration, base64ID(root), payload},
		{base64ID(leaf), expiration, base64ID(mid), payload},
	}
}

func buildDomainPolicyRows(domainID common.SHA256Output, leafSeed uint64) [][]string {
	leaf := makeLinearID(0x80, leafSeed)
	return [][]string{{base64ID(domainID), base64ID(leaf)}}
}

func buildCertExpectation(domainID common.SHA256Output, start uint64) expectedPayloadRow {
	certIDs := []common.SHA256Output{
		makeLinearID(0x40, start),
		makeLinearID(0x40, start+1),
		makeLinearID(0x40, start+2),
		makeLinearID(0x40, start+3),
	}
	certPayloadID, certLen := aggregateIDs(certIDs)
	return expectedPayloadRow{
		DomainID:    domainID,
		CertIDsID:   &certPayloadID,
		CertLen:     certLen,
		PolicyIDsID: nil,
		PolicyLen:   0,
	}
}

func buildMixedExpectation(domainID common.SHA256Output, certStart, policyStart uint64) expectedPayloadRow {
	cert := buildCertExpectation(domainID, certStart)
	policyIDs := []common.SHA256Output{
		makeLinearID(0x80, policyStart),
		makeLinearID(0x80, policyStart+1),
		makeLinearID(0x80, policyStart+2),
	}
	policyPayloadID, policyLen := aggregateIDs(policyIDs)
	cert.PolicyIDsID = &policyPayloadID
	cert.PolicyLen = policyLen
	return cert
}

func aggregateIDs(ids []common.SHA256Output) (common.SHA256Output, int) {
	sorted := append([]common.SHA256Output(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})
	buf := make([]byte, 0, len(sorted)*common.SHA256Size)
	for _, id := range sorted {
		buf = append(buf, id[:]...)
	}
	sum := sha256.Sum256(buf)
	return sum, len(buf)
}

func makeDomainID(partition int, ordinal uint64) common.SHA256Output {
	var id common.SHA256Output
	id[0] = byte(partition << 3)
	binary.BigEndian.PutUint64(id[24:], ordinal+1)
	if shard := mysql.PartitionByIdMSB(&id, mysql.NumBitsForPartitionCount(partitionCount)); int(shard) != partition {
		panic("domain id assigned to wrong partition")
	}
	return id
}

func makeLinearID(prefix byte, ordinal uint64) common.SHA256Output {
	var id common.SHA256Output
	id[0] = prefix
	binary.BigEndian.PutUint64(id[24:], ordinal)
	return id
}

func domainName(prefix string, partition int, ordinal int) string {
	return fmt.Sprintf("%sp%02d-%08d%s", prefix, partition, ordinal, domainNameSuffix)
}

func base64ID(id common.SHA256Output) string {
	return base64.StdEncoding.EncodeToString(id[:])
}

type csvWriter struct {
	file   *os.File
	writer *bufio.Writer
}

func newCSVWriter(path string) (*csvWriter, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &csvWriter{
		file:   file,
		writer: bufio.NewWriterSize(file, writerBufferSize),
	}, nil
}

func (w *csvWriter) Write(fields ...string) error {
	for i, field := range fields {
		if i > 0 {
			if _, err := w.writer.WriteString(","); err != nil {
				return err
			}
		}
		if _, err := w.writer.WriteString(`"`); err != nil {
			return err
		}
		if _, err := w.writer.WriteString(strings.ReplaceAll(field, `"`, `""`)); err != nil {
			return err
		}
		if _, err := w.writer.WriteString(`"`); err != nil {
			return err
		}
	}
	_, err := w.writer.WriteString("\n")
	return err
}

func (w *csvWriter) Close() error {
	if err := w.writer.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}
