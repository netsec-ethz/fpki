package config_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netsec-ethz/fpki/pkg/mapserver/config"
	"github.com/netsec-ethz/fpki/pkg/util"
)

// TestConfigJson checks that the map server configuration can be marshalled to JSON and back.
func TestConfigJson(t *testing.T) {
	c := &config.Config{
		UpdateAt: util.NewTimeOfDay(3, 00, 00, 00),
		UpdateTimer: util.DurationWrap{
			Duration: 24 * time.Hour,
		},
	}
	t.Logf("time is: %s", c.UpdateAt.Time)
	data, err := json.Marshal(c)
	require.NoError(t, err)
	t.Logf("JSON is: %s", string(data))
	copy := &config.Config{}
	err = json.Unmarshal(data, &copy)
	require.NoError(t, err)
}
