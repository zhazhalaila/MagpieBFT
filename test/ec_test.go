package test

import (
	"encoding/json"
	"testing"

	"github.com/zhazhalaila/BFTProtocol/consensus"
)

func TestErasureCodeWithPad(t *testing.T) {
	f := 1
	n := 4
	s := "Hello World"
	strEncode, err := json.Marshal(s)
	if err != nil {
		t.Error(err)
	}

	shards, err := consensus.ECEncode(f+1, n-f-1, strEncode)
	if err != nil {
		t.Error(err)
	}

	shards[0] = nil

	results, err := consensus.ECDecode(f+1, n-f-1, shards)
	if err != nil {
		t.Error(err)
	}

	var dec string
	err = json.Unmarshal(results, &dec)
	if err != nil {
		t.Error(err)
	}

	if dec != s {
		t.Errorf("Get = (%t), want true", dec == s)
	}
}
