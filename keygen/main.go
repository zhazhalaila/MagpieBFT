package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/zhazhalaila/BFTProtocol/keygen/keys"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

func main() {
	n := flag.Int("n", 4, "total node number")
	f := flag.Int("f", 1, "byzantine node number")
	flag.Parse()

	suite := bn256.NewSuite()
	PriShares := make([]keys.PriShare, *n)
	PubShares := make([]keys.PubShare, *n)
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), *f+1, secret, suite.RandomStream()) // Private key.
	pubPoly := priPoly.Commit(suite.G2().Point().Base())                        // Common public key.

	// Marshal binary(private key).
	for i, x := range priPoly.Shares(*n) {
		privateByte, err := x.V.MarshalBinary()
		if err != nil {
			log.Println(err)
		}
		ps := keys.PriShare{Index: x.I, Pri: privateByte}
		PriShares[i] = ps
	}
	// Marshal to json array([]byte).
	priBytes, err := json.Marshal(PriShares)
	if err != nil {
		log.Fatal(err)
	}
	// Write json array to file.
	_ = ioutil.WriteFile("../keys/"+strconv.Itoa(*n)+"/private_key.conf", priBytes, 0644)

	// Marshal binary(public key).
	for i, x := range pubPoly.Shares(*n) {
		pubByte, err := x.V.MarshalBinary()
		if err != nil {
			log.Println(err)
		}
		pB := keys.PubShare{Index: x.I, Pub: pubByte}
		PubShares[i] = pB
	}
	// Marshal to json array([]byte).
	pubBytes, err := json.Marshal(PubShares)
	if err != nil {
		log.Println(err)
	}
	// Write json array to file.
	_ = ioutil.WriteFile("../keys/"+strconv.Itoa(*n)+"/public_key.conf", pubBytes, 0644)
}
