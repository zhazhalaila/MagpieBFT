package decodekeys

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"strconv"

	"github.com/zhazhalaila/BFTProtocol/keygen/keys"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

// Decode public shares from pub-key.conf file...
func DecodePubShare(suite *bn256.Suite, n, t int) *share.PubPoly {
	// Read public keys from file.
	plan, _ := ioutil.ReadFile("../keys/" + strconv.Itoa(n) + "/public_key.conf")
	var data []keys.PubShare
	err := json.Unmarshal(plan, &data)
	if err != nil {
		log.Fatal(err)
	}

	dePubShares := make([]*share.PubShare, n)

	for i, d := range data {
		point := suite.G2().Point()
		var err error
		dePubShares[i] = &share.PubShare{}
		dePubShares[i].I = d.Index
		err = point.UnmarshalBinary(d.Pub)
		if err != nil {
			log.Fatal(err)
		}
		dePubShares[i].V = point
	}
	// Recover public key.
	pubKey, err := share.RecoverPubPoly(suite.G2(), dePubShares, t, n)
	if err != nil {
		log.Fatal(err)
	}
	return pubKey
}

func DecodePriShare(suite *bn256.Suite, n, t, id int) *share.PriShare {
	// Read private key from file.
	plan, _ := ioutil.ReadFile("../keys/" + strconv.Itoa(n) + "/private_key.conf")
	var data []keys.PriShare
	err := json.Unmarshal(plan, &data)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal binary scalar struct.
	scalar := suite.G2().Scalar()
	err = scalar.UnmarshalBinary(data[id].Pri)
	if err != nil {
		log.Fatal(err)
	}

	// Construct a prishare struct and return.
	return &share.PriShare{I: data[id].Index, V: scalar}
}
