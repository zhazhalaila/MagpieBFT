package consensus

import (
	"bytes"

	"github.com/klauspost/reedsolomon"
)

// Erasure code with padlen
func ECEncode(K, N int, data []byte) ([][]byte, error) {
	padlen := K - (len(data) % K)
	for i := 0; i < padlen; i++ {
		data = append(data, byte(padlen))
	}

	step := len(data) / K

	// If data size isn't diviable by K,
	// k-th shard will contain padlen
	shards := make([][]byte, K+N)
	for i := 0; i < K; i++ {
		shards[i] = data[i*step : (i+1)*step]
	}

	// Fill shard (K, N) with padlen
	for i := K; i < K+N; i++ {
		placeHolder := make([]byte, step)
		for j := 0; j < len(placeHolder); j++ {
			placeHolder[j] = byte(padlen)
		}
		shards[i] = placeHolder
	}

	enc, err := reedsolomon.New(K, N)
	if err != nil {
		return nil, err
	}

	err = enc.Encode(shards)
	if err != nil {
		return nil, err
	}
	return shards, nil
}

// Shards must ordered otherwise will cause index out of range
func ECDecode(K, N int, shards [][]byte) ([]byte, error) {
	dec, err := reedsolomon.New(K, N)
	if err != nil {
		return nil, err
	}

	err = dec.Reconstruct(shards)
	if err != nil {
		return nil, err
	}

	shards = shards[:K]
	result := bytes.Join(shards, []byte(""))
	padlen := result[len(result)-1]
	return result[:len(result)-int(padlen)], nil
}
