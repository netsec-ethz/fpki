package cmdflags

import (
	"flag"
	"fmt"
	"os"
	"sync"
)

// Flags for the command line:
var (
	CpuProfile      *string
	MemProfile      *string
	DBName          *string
	MultiInsertSize *int
	NumFiles        *int
	NumParsers      *int
	NumChainToCerts *int
	NumDBWriters    *int
	Strategy        *string
	FileBatch       *int
	JournalFile     *string
	// IncludePlainCSVs restores the legacy behavior of also ingesting uncompressed
	// bundle files alongside the default .gz input set.
	IncludePlainCSVs *bool
	SkipMissingFiles *bool
)

// Default values for the command line flags:
const (
	DefNumFiles      = 4
	DefNumParsers    = 32
	DefNumDechainers = 4
	DefNumDBWriters  = 32

	DefDBName = "fpki"

	DefMultiInsertSize = 10_000 // # of certificates, domains, etc inserted at once.

	DefJournalFile = "fpki-journal.json"
)

var ConfigureFlags func() = sync.OnceFunc(_configureFlags)

func _configureFlags() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s directory\n", os.Args[0])
		flag.PrintDefaults()
	}

	CpuProfile = flag.String("cpuprofile", "", "write a CPU profile to file")
	MemProfile = flag.String("memprofile", "", "write a memory profile to file")
	DBName = flag.String("dbname", DefDBName, "database name to connect to")
	MultiInsertSize = flag.Int("multiinsert", DefMultiInsertSize, "number of certificates and "+
		"domains inserted at once in the DB")
	NumFiles = flag.Int("numfiles", DefNumFiles, "Number of parallel files being read at once")
	NumParsers = flag.Int("numparsers", DefNumParsers, "Number of line parsers concurrently running")
	NumChainToCerts = flag.Int("numdechainers", DefNumDechainers, "Number of chain unrollers")
	NumDBWriters = flag.Int("numdbworkers", DefNumDBWriters, "Number of concurrent DB writers")
	Strategy = flag.String("strategy", "", "strategy to update certificates\n"+
		"\"\": full work. I.e. ingest files, coalesce, and update SMT.\n"+
		"\"onlyingest\": do not coalesce or update SMT after ingesting files.\n"+
		"\"skipingest\": only coalesce payloads of domains in the dirty table and update SMT.\n"+
		"\"onlysmtupdate\": only update the SMT.\n"+
		"\"updatectindex\": update ctlog_server_last_status from completed journal ranges.\n")
	FileBatch = flag.Int("filebatch", 0, "process files in batches of this size. If zero, then "+
		"all files are processed in one batch")
	JournalFile = flag.String("journal", DefJournalFile,
		"Journal file to keep track of progress and resume")
	IncludePlainCSVs = flag.Bool("includeplaincsvs", false,
		"include plain .csv files in addition to .gz files when listing ingest inputs; "+
			"by default only .gz files are processed")
	SkipMissingFiles = flag.Bool("skipmissingfiles", false,
		"report missing input files and continue instead of failing the batch")
	flag.Parse()
}
