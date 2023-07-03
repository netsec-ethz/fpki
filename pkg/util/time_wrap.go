package util

import (
	"encoding"
	"encoding/json"
	"flag"
	"strings"
	"time"
)

var _ (encoding.TextUnmarshaler) = (*TimeOfDayWrap)(nil)
var _ (encoding.TextMarshaler) = TimeOfDayWrap{}
var _ (json.Unmarshaler) = (*TimeOfDayWrap)(nil)
var _ (json.Marshaler) = TimeOfDayWrap{}
var _ (flag.Value) = (*TimeOfDayWrap)(nil)

// TimeOfDayWrap is a wrapper to enable marshalling and unmarshalling of durations
// with the custom format. Based on DurWrap.
type TimeOfDayWrap struct {
	time.Time
}

// NewTimeOfDay constructs a TimeOfDayWrap from the arguments.
func NewTimeOfDay(hour, minute, second, nanosecond uint) TimeOfDayWrap {
	if hour > 23 {
		hour = 23
	}
	if minute > 59 {
		minute = 59
	}
	if second > 59 {
		second = 59
	}
	if nanosecond > 999_999_999 {
		nanosecond = 999_999_999
	}

	return TimeOfDayWrap{
		Time: time.Date(0, 1, 1, int(hour), int(minute), int(second), int(nanosecond), time.UTC),
	}
}

func (t *TimeOfDayWrap) UnmarshalText(text []byte) error {
	return t.Set(string(text))
}

func (t *TimeOfDayWrap) Set(text string) error {
	var err error
	t.Time, err = ParseTimeOfDay(text)
	return err
}

func (t TimeOfDayWrap) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t *TimeOfDayWrap) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	return t.Set(s)
}

func (t TimeOfDayWrap) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// String returns the string with the TimeOnly specification plus milli, micro, or nano seconds,
// depending which one would output a shorter string.
func (t TimeOfDayWrap) String() string {
	nanos := t.Nanosecond()
	decimalCount := 0

	for ; nanos > 0; decimalCount += 3 {
		nanos = nanos % Pow(10, uint(6-decimalCount))
	}

	// If there is a decimal count > 0, specify it as part of the layout.
	layout := time.TimeOnly
	if decimalCount > 0 {
		layout += "." + strings.Repeat("0", decimalCount)
	}

	return t.Format(layout)
}
