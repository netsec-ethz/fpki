package db

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/netsec-ethz/fpki/pkg/mapserver/trie"
	"github.com/stretchr/testify/require"
)

func Test_Insert_Read(t *testing.T) {

	conn, err := Connect_old()
	require.NoError(t, err, "dbinit")

	for i := 0; i < 50000; i++ {
		newKVPair := getKeyValuePair(i*1000, i*1000+999, generateRandomBytes())
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()
		start := time.Now()
		err = conn.UpdateKeyValuePairBatches(ctx, newKVPair)
		require.NoError(t, err, "db insert")
		end := time.Now()
		fmt.Println("iteration ", i, " current nodes: ", i*1000, "time ", end.Sub(start))
	}
}

func getKeyValuePair(startIdx, endIdx int, content []byte) []KeyValuePair {
	result := []KeyValuePair{}
	for i := startIdx; i <= endIdx; i++ {
		keyHash := trie.Hasher([]byte(strconv.Itoa(i)))
		keyString := hex.EncodeToString(keyHash)
		result = append(result, KeyValuePair{Key: keyString, Value: content})
	}
	return result
}

func generateRandomBytes() []byte {
	token := make([]byte, 1000)
	rand.Read(token)
	return token
}
