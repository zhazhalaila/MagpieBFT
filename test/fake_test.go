package test

import (
	"testing"

	"github.com/zhazhalaila/BFTProtocol/message"
)

func TestFake(t *testing.T) {
	bs := 2
	clientId := 1
	reqCount := 2
	peerId := 3

	txs := message.FakeBatchTx(bs, clientId, reqCount, peerId)
	if len(txs) != bs {
		t.Errorf("Get batchsize len = %d, want %d", len(txs), bs)
	}

	for i := 0; i < bs; i++ {
		if len(txs[i]) != 250 {
			t.Errorf("Get tx len = %d, want %d", len(txs[i]), bs)
		}
	}
}
