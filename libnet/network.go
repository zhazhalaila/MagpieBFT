package libnet

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type Network struct {
	logger    *log.Logger         // Global log.
	mu        sync.RWMutex        // RWLock to prevent race condition.
	port      string              // Network port.
	listener  net.Listener        // Network listener.
	stopCh    chan bool           // Stop server.
	consumeCh chan message.ReqMsg // Upon receive msg from network send msg to channel.
	releaseCh chan bool           // Consensus module release.
	conns     map[string]net.Conn // Cache all remote connection. e.g. {'RemoteAddr': net.conn}.
}

// Create network.
func MakeNetwork(port string, logger *log.Logger, consumeCh chan message.ReqMsg, releaseCh chan bool) *Network {
	rn := &Network{}
	rn.port = port
	rn.logger = logger
	rn.stopCh = make(chan bool)
	rn.consumeCh = consumeCh
	rn.releaseCh = releaseCh
	rn.conns = make(map[string]net.Conn)
	return rn
}

// Start network.
func (rn *Network) Start() {
	var err error
	rn.listener, err = net.Listen("tcp", rn.port)

	if err != nil {
		rn.logger.Fatalf("Socket listen port %s failed, %s", rn.port, err)
		os.Exit(1)
	}

	rn.logger.Printf("Network port %s\n", rn.port)

	for {
		conn, err := rn.listener.Accept()
		if err != nil {
			select {
			case <-rn.stopCh:
				return
			default:
				rn.logger.Fatal("accept error:", err)
			}
		}
		// Store connection
		rn.mu.Lock()
		rn.conns[conn.RemoteAddr().String()] = conn
		rn.mu.Unlock()
		go rn.handleConn(conn)
	}
}

// Shutdown network (local test.)
func (rn *Network) Shutdown() {
	close(rn.stopCh)
	rn.listener.Close()
	fmt.Println("close consume channnel")
	close(rn.consumeCh)
	// Wait for all goroutine done (create by consensus module)
	<-rn.releaseCh
}

// Handle connection
func (rn *Network) handleConn(conn net.Conn) {
	defer func() {
		// delete connection from network and close connection.
		rn.logger.Printf("Remote machine [%s] close connection.\n", conn.RemoteAddr().String())
		rn.mu.Lock()
		delete(rn.conns, conn.RemoteAddr().String())
		rn.mu.Unlock()
		conn.Close()
	}()

	dec := json.NewDecoder(conn)

	for {
		var req message.ReqMsg
		if err := dec.Decode(&req); err == io.EOF {
			// remote machine close connection.
			break
		} else if err != nil {
			// network error. e.g. write data to a closed connection.
			rn.logger.Println(err)
			break
		}
		// send data to channel.
		rn.consumeCh <- req
	}
}
