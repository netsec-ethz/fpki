package tests

import (
	"fmt"
	"os"

	"github.com/stretchr/testify/require"
)

type T interface {
	require.TestingT
	Helper()
	Name() string
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
