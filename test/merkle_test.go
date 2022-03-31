package test

import (
	"log"
	"strconv"
	"testing"

	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
)

func TestMerkleTree(t *testing.T) {
	var shards [][]byte
	for i := 0; i < 5; i++ {
		shards = append(shards, []byte(strconv.Itoa(i)))
	}

	mt, err := merkletree.MakeMerkleTree(shards)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		branch := merkletree.GetMerkleBranch(i, mt)
		ok := merkletree.MerkleTreeVerify(shards[i], mt[1], branch, i)
		if !ok {
			t.Errorf("Verify = %t; want true", ok)
		}
	}
}
