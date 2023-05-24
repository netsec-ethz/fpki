package tests

import "github.com/stretchr/testify/require"

type T interface {
	require.TestingT
	Helper()
	Name() string
}
