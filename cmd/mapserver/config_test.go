package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestConfigJson(t *testing.T) {
	config := &Config{
		UpdateAt: util.NewTimeOfDay(3, 00, 00, 00),
		UpdateTimer: util.DurationWrap{
			Duration: 24 * time.Hour,
		},
	}
	t.Logf("time is: %s", config.UpdateAt.Time)
	data, err := json.Marshal(config)
	require.NoError(t, err)
	t.Logf("JSON is: %s", string(data))
	copy := &Config{}
	err = json.Unmarshal(data, &copy)
	require.NoError(t, err)
}
