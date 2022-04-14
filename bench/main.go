package main

import (
	"time"

	"github.com/zhazhalaila/BFTProtocol/libclient"
)

func main() {
	filePath := "../localAddress.txt"
	n := 4
	f := 1

	client := libclient.NewClient(n, f, 0)
	client.ReadAddress(filePath, n)

	client.ConnectRemotePeers()

	// If client connected peers, no response
	// wait 100 millisecond to wait connect done
	time.Sleep(100 * time.Millisecond)

	client.PeersConnectPeers()

	// As above
	time.Sleep(100 * time.Millisecond)

	for i := 0; i < 10000; i++ {
		client.SendRequest()
		time.Sleep(300 * time.Millisecond)
	}
}
