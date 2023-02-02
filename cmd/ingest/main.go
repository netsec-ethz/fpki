package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"

	"github.com/netsec-ethz/fpki/pkg/db"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

func main() {
	os.Exit(mainFunction())
}
func mainFunction() int {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s directory\n", os.Args[0])
		flag.PrintDefaults()
	}
	cpuProfile := flag.String("cpuprofile", "", "write a CPU profile to file")
	memProfile := flag.String("memprofile", "", "write a memory profile to file")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		return 1
	}

	// Profiling:
	stopProfiles := func() {
		if *cpuProfile != "" {
			pprof.StopCPUProfile()
		}
		if *memProfile != "" {
			f, err := os.Create(*memProfile)
			exitIfError(err)
			err = pprof.WriteHeapProfile(f)
			exitIfError(err)
		}
	}
	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		exitIfError(err)
		err = pprof.StartCPUProfile(f)
		exitIfError(err)
	}
	defer stopProfiles()

	// Signals catching:
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		stopProfiles()
	}()

	conn, err := db.Connect(nil)
	exitIfError(err)

	gzFiles, csvFiles := listOurFiles(flag.Arg(0))
	fmt.Printf("# gzFiles: %d, # csvFiles: %d\n", len(gzFiles), len(csvFiles))

	// Truncate DB.
	exitIfError(conn.TruncateAllTables())

	// Update certificates and chains.
	proc := NewProcessor(conn)
	proc.AddGzFiles(gzFiles)
	proc.AddCsvFiles(csvFiles)
	exitIfError(proc.Wait())

	// Close DB and check errors.
	err = conn.Close()
	exitIfError(err)
	return 0
}

func listOurFiles(dir string) (gzFiles, csvFiles []string) {
	entries, err := ioutil.ReadDir(dir)
	exitIfError(err)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "bundled" {
			// Use all *.gz in this directory.
			d := filepath.Join(dir, e.Name())
			gzFiles, err = filepath.Glob(fmt.Sprintf("%s/*.gz", d))
			exitIfError(err)
			csvFiles, err = filepath.Glob(fmt.Sprintf("%s/*.csv", dir))
			exitIfError(err)
		} else {
			gzs, csvs := listOurFiles(filepath.Join(dir, e.Name()))
			gzFiles = append(gzFiles, gzs...)
			csvFiles = append(csvFiles, csvs...)
		}
	}
	return
}

func exitIfError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
