package fastcsv

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
)

const (
	CertificateColumn = 3
	CertChainColumn   = 4
)

type Disposition int

const (
	ParseFastOK Disposition = iota
	ParseFallbackNeeded
	ParseHardError
)

// String returns the stable diagnostic label used in logs and tests.
func (d Disposition) String() string {
	switch d {
	case ParseFastOK:
		return "fast_ok"
	case ParseFallbackNeeded:
		return "fallback_needed"
	case ParseHardError:
		return "hard_error"
	default:
		return "unknown"
	}
}

type Result struct {
	Disposition     Disposition
	CertField       []byte
	ChainField      []byte
	ExpirationField []byte
	Reason          string
}

// ParsedLine contains only the ingest-relevant columns extracted from one CSV row.
type ParsedLine struct {
	CertField       []byte
	ChainField      []byte
	ExpirationField []byte
	Number          int
}

var stderr io.Writer = os.Stderr

// SetStderr overrides the package logger destination and returns a restore function.
func SetStderr(w io.Writer) func() {
	old := stderr
	stderr = w
	return func() {
		stderr = old
	}
}

// ParseLine parses one physical CSV row using the fast path when safe and falls back per row.
func ParseLine(rawLine []byte, filename string, lineNo int) (ParsedLine, error) {
	rawLine = bytes.TrimRight(rawLine, "\r\n")
	result := ParseRowFast(rawLine)
	switch result.Disposition {
	case ParseFastOK:
		return ParsedLine{
			CertField:       result.CertField,
			ChainField:      result.ChainField,
			ExpirationField: result.ExpirationField,
			Number:          lineNo,
		}, nil
	case ParseFallbackNeeded:
		fmt.Fprintf(stderr,
			"fast-csv fallback: file=%s line=%d disposition=%s reason=%s\n",
			filename, lineNo, result.Disposition, result.Reason)
		parsed, err := parseRowSlow(rawLine)
		if err != nil {
			return ParsedLine{}, fmt.Errorf("reading %s: at line %d: %w", filename, lineNo, err)
		}
		parsed.Number = lineNo
		return parsed, nil
	case ParseHardError:
		fmt.Fprintf(stderr,
			"fast-csv reject: file=%s line=%d disposition=%s reason=%s\n",
			filename, lineNo, result.Disposition, result.Reason)
		return ParsedLine{}, fmt.Errorf("reading %s: at line %d: %s", filename, lineNo, result.Reason)
	default:
		return ParsedLine{}, fmt.Errorf("reading %s: at line %d: unknown parse disposition", filename, lineNo)
	}
}

// ParseRowFast classifies one row for the fast path without invoking the slower CSV parser.
func ParseRowFast(rawLine []byte) Result {
	if len(rawLine) == 0 {
		return Result{Disposition: ParseHardError, Reason: "empty_line"}
	}
	if bytes.IndexByte(rawLine, '"') >= 0 {
		return Result{Disposition: ParseFallbackNeeded, Reason: "unsupported_quotes"}
	}

	fieldIndex := 0
	fieldStart := 0
	certStart, certEnd := -1, -1
	chainStart, chainEnd := -1, -1
	lastStart, lastEnd := -1, -1

	for i := 0; i <= len(rawLine); i++ {
		if i < len(rawLine) && rawLine[i] != ',' {
			continue
		}
		fieldEnd := i
		switch fieldIndex {
		case CertificateColumn:
			certStart, certEnd = fieldStart, fieldEnd
		case CertChainColumn:
			chainStart, chainEnd = fieldStart, fieldEnd
		}
		lastStart, lastEnd = fieldStart, fieldEnd
		fieldIndex++
		fieldStart = i + 1
	}

	if certStart < 0 || chainStart < 0 || lastStart < 0 {
		return Result{Disposition: ParseHardError, Reason: "too_few_fields"}
	}
	if certStart == certEnd {
		return Result{Disposition: ParseHardError, Reason: "missing_certificate_field"}
	}
	if !looksLikeExpirationField(rawLine[lastStart:lastEnd]) {
		return Result{Disposition: ParseFallbackNeeded, Reason: "invalid_expiration_shape"}
	}

	return Result{
		Disposition:     ParseFastOK,
		CertField:       rawLine[certStart:certEnd],
		ChainField:      rawLine[chainStart:chainEnd],
		ExpirationField: rawLine[lastStart:lastEnd],
	}
}

func parseRowSlow(rawLine []byte) (ParsedLine, error) {
	r := csv.NewReader(bytes.NewReader(rawLine))
	r.FieldsPerRecord = -1
	fields, err := r.Read()
	if err != nil {
		return ParsedLine{}, err
	}
	if len(fields) <= CertChainColumn {
		return ParsedLine{}, fmt.Errorf("too few fields")
	}
	expirationField := fields[len(fields)-1]
	if expirationField == "" {
		return ParsedLine{}, fmt.Errorf("missing expiration field")
	}
	return ParsedLine{
		CertField:       []byte(fields[CertificateColumn]),
		ChainField:      []byte(fields[CertChainColumn]),
		ExpirationField: []byte(expirationField),
	}, nil
}

func looksLikeExpirationField(field []byte) bool {
	if len(field) < 3 {
		return false
	}
	dot := bytes.IndexByte(field, '.')
	if dot <= 0 || dot == len(field)-1 {
		return false
	}
	for _, b := range field[:dot] {
		if b < '0' || b > '9' {
			return false
		}
	}
	for _, b := range field[dot+1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}
