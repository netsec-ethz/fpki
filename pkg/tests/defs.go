package tests

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/stretchr/testify/require"
)

type T interface {
	require.TestingT
	Helper()
	Name() string
	Logf(format string, args ...any)
	Skipf(format string, args ...any)
}

type RuntimeTest struct {
	TestName string
}

var _ T = RuntimeTest{}

func NewTestObject(name string) RuntimeTest {
	return RuntimeTest{
		TestName: name,
	}
}

func (RuntimeTest) Helper()         {}
func (rt RuntimeTest) Name() string { return rt.TestName }
func (RuntimeTest) FailNow()        { os.Exit(1) }
func (RuntimeTest) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
func (RuntimeTest) Logf(format string, args ...interface{}) {
	args = append([]any{time.Now().Format(time.Stamp)}, args...)
	fmt.Printf("\t%s: "+format+"\n", args...)
}
func (r RuntimeTest) Skipf(format string, args ...any) {
	r.Logf(format, args...)
	runtime.Goexit()
}
