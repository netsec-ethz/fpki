package fastcsv

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFastCSVParserDispositionFastOK(t *testing.T) {
	row := []byte("a,b,c,QUJD,REVG;R0hJ,x,y,1700000000.0")

	got := ParseRowFast(row)

	require.Equal(t, ParseFastOK, got.Disposition)
	require.Equal(t, "QUJD", string(got.CertField))
	require.Equal(t, "REVG;R0hJ", string(got.ChainField))
	require.Equal(t, "1700000000.0", string(got.ExpirationField))
	require.Empty(t, got.Reason)
}

func TestFastCSVParserDispositionFallbackNeeded(t *testing.T) {
	row := []byte(`a,b,c,"QUJD","REVG;R0hJ",x,y,1700000000.0`)

	got := ParseRowFast(row)

	require.Equal(t, ParseFallbackNeeded, got.Disposition)
	require.Equal(t, "unsupported_quotes", got.Reason)
}

func TestFastCSVParserDispositionHardError(t *testing.T) {
	row := []byte("a,b,c")

	got := ParseRowFast(row)

	require.Equal(t, ParseHardError, got.Disposition)
	require.Equal(t, "too_few_fields", got.Reason)
	require.Nil(t, got.CertField)
	require.Nil(t, got.ChainField)
	require.Nil(t, got.ExpirationField)
}

func TestParseLineFallbackUsesSlowParserAndLogsToStderr(t *testing.T) {
	var stderr bytes.Buffer
	restore := SetStderr(&stderr)
	defer restore()

	row := []byte("\"a\",\"b\",\"c\",\"QUJD\",\"REVG;R0hJ\",\"x\",\"y\",\"1700000000.0\"\n")

	got, err := ParseLine(row, "quoted.csv", 12)
	require.NoError(t, err)
	require.Equal(t, 12, got.Number)
	require.Equal(t, "QUJD", string(got.CertField))
	require.Equal(t, "REVG;R0hJ", string(got.ChainField))
	require.Equal(t, "1700000000.0", string(got.ExpirationField))
	require.Contains(t, stderr.String(), "fast-csv fallback:")
	require.Contains(t, stderr.String(), "file=quoted.csv")
	require.Contains(t, stderr.String(), "line=12")
	require.Contains(t, stderr.String(), "disposition=fallback_needed")
	require.Contains(t, stderr.String(), "reason=unsupported_quotes")
}

func TestParseLineHardErrorLogsToStderr(t *testing.T) {
	var stderr bytes.Buffer
	restore := SetStderr(&stderr)
	defer restore()

	_, err := ParseLine([]byte("a,b,c\n"), "broken.csv", 7)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too_few_fields")
	require.Contains(t, stderr.String(), "fast-csv reject:")
	require.Contains(t, stderr.String(), "file=broken.csv")
	require.Contains(t, stderr.String(), "line=7")
	require.Contains(t, stderr.String(), "disposition=hard_error")
	require.Contains(t, stderr.String(), "reason=too_few_fields")
}
