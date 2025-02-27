package tests

import (
	"fmt"
	"os"
	"runtime"
	"testing"
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

// Run finds out what type of testing object we have in t, and passes it to the fcn function.
// The types it understands are *testing.T and *testing.B.
func Run(t T, name string, fcn func(T)) {
	switch v := t.(type) {
	case *testing.T:
		v.Run(name, func(t *testing.T) {
			fcn(v)
		})
	case *testing.B:
		v.Run(name, func(t *testing.B) {
			fcn(v)
		})
	default:
		t.Errorf("unsupported type %T", v)
		t.FailNow()
	}
}
