package util

import "time"

func TimeFromSecs(secs int) time.Time {
	return time.Unix(int64(secs), 0)
}

func SecsFromTime(t time.Time) int {
	return int(t.Unix())
}