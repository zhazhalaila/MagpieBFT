package merkletree

import (
	"crypto/sha256"
	"errors"
	"math"
)

func MakeMerkleTree(shards [][]byte) ([][32]byte, error) {
	n := len(shards)
	if n < 1 {
		return nil, errors.New("too few shards")
	}
	bottomrow := int(math.Pow(2, math.Ceil(math.Log2(float64(n)))))
	var mt [][32]byte
	for i := 0; i < 2*bottomrow; i++ {
		var placeHolder [32]byte
		mt = append(mt, placeHolder)
	}

	for i := 0; i < n; i++ {
		x := sha256.Sum256(shards[i])
		mt[bottomrow+i] = x
	}

	for i := bottomrow - 1; i > 0; i-- {
		var parent [32]byte
		for j := 0; j < len(parent); j++ {
			parent[j] = mt[i*2][j] + mt[i*2+1][j]
		}
		x := sha256.Sum256(parent[:])
		mt[i] = x
	}

	return mt, nil
}

func GetMerkleBranch(index int, mt [][32]byte) [][32]byte {
	var res [][32]byte
	t := index + (len(mt) >> 1)
	for t > 1 {
		res = append(res, mt[t^1])
		t /= 2
	}
	return res
}

func MerkleTreeVerify(val []byte, rootHash [32]byte, branch [][32]byte, index int) bool {
	tmp := sha256.Sum256(val)
	tIndex := index

	for _, br := range branch {
		var parent [32]byte
		if tIndex&1 == 1 {
			for i := 0; i < len(parent); i++ {
				parent[i] = br[i] + tmp[i]
			}
		} else {
			for i := 0; i < len(parent); i++ {
				parent[i] = tmp[i] + br[i]
			}
		}
		tmp = sha256.Sum256(parent[:])
		tIndex >>= 1
	}

	if tmp == rootHash {
		return true
	} else {
		return false
	}
}
