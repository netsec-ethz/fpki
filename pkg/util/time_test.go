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

func TestNextTimeOfDay(t *testing.T) {
	now := time.Now().UTC()
	t.Logf("now:\t %s", now)

	// Make the TimeOfDayWrap `now` to be in the past and call it `yesterday`.
	yesterday := TimeOfDayWrap{
		Time: now.AddDate(0, 0, -1),
	}
	require.True(t, yesterday.Before(now))
	require.Equal(t, now.Hour(), yesterday.Hour())
	require.Equal(t, now.Minute(), yesterday.Minute())
	require.Equal(t, now.Second(), yesterday.Second())
	require.Equal(t, now.Nanosecond(), yesterday.Nanosecond())
	// Test it.
	next := yesterday.NextTimeOfDay()
	t.Logf("yesterda:\t %s", yesterday.Time)
	t.Logf("next:\t %s", next)
	require.False(t, next.Before(now))
	require.Equal(t, now.Hour(), next.Hour())
	require.Equal(t, now.Minute(), next.Minute())
	require.Equal(t, now.Second(), next.Second())
	require.Equal(t, now.Nanosecond(), next.Nanosecond())
	// At most 1 day in the future.
	require.LessOrEqual(t, next.Sub(now), 24*time.Hour)

	// Make the TimeOfDayWrap `now` to be in the future and call it `got`.
	tomorrow := TimeOfDayWrap{
		Time: now.AddDate(0, 0, 1),
	}
	require.True(t, tomorrow.After(now))
	require.Equal(t, now.Hour(), tomorrow.Hour())
	require.Equal(t, now.Minute(), tomorrow.Minute())
	require.Equal(t, now.Second(), tomorrow.Second())
	require.Equal(t, now.Nanosecond(), tomorrow.Nanosecond())
	// Test it.
	next = tomorrow.NextTimeOfDay()
	t.Logf("tomorrow:\t %s", tomorrow.Time)
	t.Logf("next:\t %s", next)
	require.False(t, next.Before(now))
	require.Equal(t, now.Hour(), next.Hour())
	require.Equal(t, now.Minute(), next.Minute())
	require.Equal(t, now.Second(), next.Second())
	require.Equal(t, now.Nanosecond(), next.Nanosecond())
	// At most 1 day in the future.
	require.LessOrEqual(t, next.Sub(now), 24*time.Hour)
}
