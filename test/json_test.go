package test

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"reflect"
	"testing"

	"github.com/zhazhalaila/BFTProtocol/message"
)

func TestMarshalAndUnMarshal(t *testing.T) {
	// Construct echo message
	echo := message.ECHO{}
	echo.Branch = make([][32]byte, 4)
	echo.Shard = append(echo.Shard, []byte("Hello")...)
	echo.RootHash = sha256.Sum256(echo.Shard)
	for i := 0; i < 4; i++ {
		echo.Branch[i] = echo.RootHash
	}

	// Marshal
	echoEncoded, err := json.Marshal(echo)
	if err != nil {
		log.Fatal(err)
	}

	// Unmarshal
	var decoded message.ECHO
	err = json.Unmarshal(echoEncoded, &decoded)
	if err != nil {
		log.Fatal(err)
	}

	// Equal
	ok := reflect.DeepEqual(echo, decoded)
	if !ok {
		t.Errorf("Decoded = %t; want true", ok)
	}
}
