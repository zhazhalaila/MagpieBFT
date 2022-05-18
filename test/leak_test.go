package test

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/fortytw2/leaktest"
	"github.com/zhazhalaila/BFTProtocol/consensus"
	"github.com/zhazhalaila/BFTProtocol/libnet"
	"github.com/zhazhalaila/BFTProtocol/message"
)

func TestLeakGoroutine(t *testing.T) {
	defer leaktest.CheckTimeout(t, 1100*time.Millisecond)()

	// Config logger.
	var b bytes.Buffer
	logger := log.New(&b, "logger: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Print("Start server.")

	// Create consume, stopCh and release channel
	consumeCh := make(chan *message.ConsensusMsg, 100*100)
	stopCh := make(chan bool)
	releaseCh := make(chan bool)
	server := libnet.MakeNetwork(":8000", logger, consumeCh, stopCh, releaseCh)
	go server.Start()

	// Create consensus module
	cm := consensus.MakeConsensusModule(logger, server, releaseCh, 4, 1, 0)
	go cm.Consume(consumeCh, stopCh)

	// Wait for server start listen
	time.Sleep(1 * time.Second)

	// create client
	conn, err := net.Dial("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// send msg
	for i := 0; i < 10000; i++ {
		msg := message.ReqMsg{
			ConsensusMsgField: &message.ConsensusMsg{
				Round: i,
				PCBCReqField: &message.PCBCReq{
					Proposer: 2,
					Req:      i,
				},
			},
		}
		msgJs, err := json.Marshal(msg)
		if err != nil {
			log.Fatal(err)
		}
		conn.Write(msgJs)
	}

	// close connection.
	conn.Close()

	// network shutdown
	server.Shutdown()
	b.WriteTo(os.Stdout)
}
