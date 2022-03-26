package main

import (
	"flag"
	"log"
	"os"

	"github.com/zhazhalaila/BFTProtocol/consensus"
	"github.com/zhazhalaila/BFTProtocol/libnet"
	"github.com/zhazhalaila/BFTProtocol/message"
)

func main() {
	port := flag.String("port", ":8000", "network port number")
	path := flag.String("path", "log.txt", "log file path")
	flag.Parse()

	// Create file to store log.
	logPath := "../" + *path
	logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file : %v", err)
	}

	defer logFile.Close()

	// Config logger.
	logger := log.New(logFile, "logger: ", log.Ldate|log.Ltime|log.Lshortfile)
	logger.Print("Start server.")

	// Create consume and release channel
	consumeCh := make(chan message.ReqMsg, 100*100)
	releaseCh := make(chan bool)

	// Create network.
	rn := libnet.MakeNetwork(*port, logger, consumeCh, releaseCh)

	// Create consensus module.
	cm := consensus.MakeConsensusModule(consumeCh, releaseCh)
	go cm.Run()

	// Start server.
	rn.Start()
}
