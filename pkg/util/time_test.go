package util

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/tests"
	"github.com/stretchr/testify/require"
)

const layout = "11:22:33.000000"

func TestNewTimeOfDay(t *testing.T) {
	cases := map[string]struct {
		hour, minute, second, nanosecond uint
		expected                         string
	}{
		"simple": {
			hour:       1,
			minute:     1,
			second:     1,
			nanosecond: 1,
			expected:   "01:01:01.000000001",
		},
		"no_nanosecs": {
			hour:       1,
			minute:     1,
			second:     1,
			nanosecond: 0,
			expected:   "01:01:01",
		},
		"hour_out": {
			hour:       24,
			minute:     1,
			second:     1,
			nanosecond: 1,
			expected:   "23:01:01.000000001",
		},
		"minute_out": {
			hour:       1,
			minute:     60,
			second:     1,
			nanosecond: 1,
			expected:   "01:59:01.000000001",
		},
		"second_out": {
			hour:       1,
			minute:     1,
			second:     59,
			nanosecond: 1,
			expected:   "01:01:59.000000001",
		},
		"nanosec_out": {
			hour:       1,
			minute:     1,
			second:     1,
			nanosecond: 1_000_000_000,
			expected:   "01:01:01.999999999",
		},
		"foo": {
			hour:       3,
			minute:     00,
			second:     00,
			nanosecond: 00,
			expected:   "03:00:00",
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := NewTimeOfDay(tc.hour, tc.minute, tc.second, tc.nanosecond)
			t.Logf("time is: %s", got.Time)
			require.Equal(t, tc.expected, got.String())

			// Check validity of the created object via JSON marshalling.
			data, err := json.Marshal(got)
			require.NoError(t, err)
			copy := TimeOfDayWrap{}
			err = json.Unmarshal(data, &copy)
			require.NoError(t, err)
			require.Equal(t, got, copy)
		})
	}
}

func TestParseTimeOfDay(t *testing.T) {
	cases := map[string]struct {
		s            string
		expectError  bool
		expectedTime time.Time
	}{
		"just_seconds": {
			s:            "13:33:44",
			expectedTime: tests.MustParseTime(t, time.TimeOnly, "13:33:44"),
		},
		"with_microsecs": {
			s:            "13:33:44.123",
			expectedTime: tests.MustParseTime(t, time.TimeOnly, "13:33:44.123"),
		},
		"with_millisecs": {
			s:            "13:33:44.123456",
			expectedTime: tests.MustParseTime(t, time.TimeOnly, "13:33:44.123456"),
		},
		"with_nanosecs": {
			s:            "13:33:44.123456789",
			expectedTime: tests.MustParseTime(t, time.TimeOnly, "13:33:44.123456789"),
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			got, err := ParseTimeOfDay(tc.s)
			t.Logf("got time: %s nanos: %d", got, got.Nanosecond())
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedTime, got)
			}
		})
	}
}

func TestTimeOfDayWrap(t *testing.T) {
	cases := map[string]struct {
		Time           time.Time
		expectError    bool
		expectedString string
	}{
		"simple": {
			Time:           tests.MustParseTime(t, time.TimeOnly, "13:35:55"),
			expectedString: "13:35:55",
		},
		"with_millisecs": {
			Time:           tests.MustParseTime(t, time.TimeOnly, "13:35:55.123"),
			expectedString: "13:35:55.123",
		},
		"with_microsecs": {
			Time:           tests.MustParseTime(t, time.TimeOnly, "13:35:55.123456"),
			expectedString: "13:35:55.123456",
		},
		"with_nanosecs": {
			Time:           tests.MustParseTime(t, time.TimeOnly, "13:35:55.123456789"),
			expectedString: "13:35:55.123456789",
		},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			wrap := TimeOfDayWrap{
				Time: tc.Time,
			}
			got, err := wrap.MarshalText()
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expectedString, string(got))
			}
			data, err := json.Marshal(wrap)
			t.Logf("%s", string(data))
			if tc.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				wrap = TimeOfDayWrap{}
				err = json.Unmarshal(data, &wrap)
				require.NoError(t, err)
			}
		})
	}
}
