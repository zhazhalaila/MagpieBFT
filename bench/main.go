package main

import (
	"flag"
	"time"

	"github.com/zhazhalaila/BFTProtocol/libclient"
)

func main() {
	filePath := "../localAddress.txt"
	n := flag.Int("n", 4, "total node number")
	f := flag.Int("f", 1, "byzantine node number")
	clientId := flag.Int("ci", 0, "client identify")
	reqCount := flag.Int("rq", 1, "request count")
	batchSize := flag.Int("bs", 1, "batch size")
	flag.Parse()

	client := libclient.NewClient(*n, *f, *clientId, *reqCount, *batchSize)
	client.ReadAddress(filePath, *n)

	client.ConnectRemotePeers()

	// If client connected peers, no response
	// wait 100 millisecond for connect done
	time.Sleep(100 * time.Millisecond)

	client.PeersConnectPeers()

	// As above
	time.Sleep(100 * time.Millisecond)

	// Send request
	client.SendRequest()
	// Wait
	<-client.Done()
	// Compute latency
	client.ComputeLatency()
	// Disconnect from remote peer
	client.Disconnect()
}
