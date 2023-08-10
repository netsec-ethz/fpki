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

type RuntimeTest struct{}

var _ T = RuntimeTest{}

func NewTestObject() RuntimeTest {
	return RuntimeTest{}
}

func (RuntimeTest) Helper()      {}
func (RuntimeTest) Name() string { return "runtime tester object" }
func (RuntimeTest) FailNow()     { os.Exit(1) }
func (RuntimeTest) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}
