package verify

import (
	"crypto/sha256"
	"encoding/json"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

// Convert struct to byte
func ConvertStructToHashBytes(s interface{}) ([]byte, error) {
	converted, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	convertedHash := sha256.Sum256(converted)
	return convertedHash[:], nil
}

// Generate partial share
func GenShare(data []byte, suite *bn256.Suite, priKey *share.PriShare) ([]byte, error) {
	sig, err := tbls.Sign(suite, priKey, data)
	if err != nil {
		return sig, err
	}
	return sig, nil
}

// Compute siganture
func ComputeSignature(data []byte, suite *bn256.Suite, shares [][]byte, pubKey *share.PubPoly, n, t int) ([]byte, error) {
	signature, err := tbls.Recover(suite, pubKey, data, shares, t, n)
	if err != nil {
		return signature, err
	}
	return signature, nil
}

// Verify signature
func SignatureVerify(data []byte, sig []byte, suite *bn256.Suite, pubKey *share.PubPoly) error {
	err := bls.Verify(suite, pubKey.Commit(), data, sig)
	if err != nil {
		return err
	}
	return nil
}

// Verify share
func ShareVerify(data []byte, share []byte, suite *bn256.Suite, pubKey *share.PubPoly) error {
	err := tbls.Verify(suite, pubKey, data, share)
	if err != nil {
		return err
	}
	return nil
}
