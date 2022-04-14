package main

import (
	"flag"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/zhazhalaila/BFTProtocol/consensus"
	"github.com/zhazhalaila/BFTProtocol/libnet"
	"github.com/zhazhalaila/BFTProtocol/message"
)

func PrintMemUsage(logger *log.Logger) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	logger.Printf("Alloc = %v MiB.\n", bToMb(m.Alloc))
	logger.Printf("Sys = %v MiB", bToMb(m.Sys))
	logger.Printf("NumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func main() {
	path := flag.String("path", "log.txt", "log file path")
	port := flag.String("port", ":8000", "network port number")
	id := flag.Int("id", 0, "assign a unique number to different server")
	n := flag.Int("n", 4, "total node number")
	f := flag.Int("f", 1, "byzantine node number")
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

	// Create consume. stopCh and release channel
	consumeCh := make(chan *message.ConsensusMsg, 10000)
	stopCh := make(chan bool)
	releaseCh := make(chan bool)

	// Create network.
	rn := libnet.MakeNetwork(*port, logger, consumeCh, stopCh, releaseCh)

	// Create consensus module.
	cm := consensus.MakeConsensusModule(logger, rn, releaseCh, *n, *f, *id)
	go cm.Consume(consumeCh, stopCh)

	go func() {
		for {
			time.Sleep(10 * time.Second)
			logger.Printf("Runtime Goroutine = [%d].\n", runtime.NumGoroutine())
			PrintMemUsage(logger)
		}
	}()

	// Start server.
	rn.Start()
}
