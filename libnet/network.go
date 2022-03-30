package libnet

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

const (
	PeerOP   = iota
	ClientOP = iota
)

type Network struct {
	// RWMutex to prevent data race
	mu sync.RWMutex
	// Record connected clients
	// Remote peers
	clients map[int]net.Conn
	peers   map[int]net.Conn
	// Global log
	// Network port
	// Network listener
	logger   *log.Logger
	port     string
	listener net.Listener
	// Stop channel to stop network
	// Consume channel send data to consensus module
	// Release channel to exit goroutine upon receive release signal from consensus
	stopCh    chan bool
	consumeCh chan *message.ConsensusMsg
	releaseCh chan bool
}

// Create network.
func MakeNetwork(port string, logger *log.Logger, consumeCh chan *message.ConsensusMsg, stopCh, releaseCh chan bool) *Network {
	rn := &Network{}
	rn.clients = make(map[int]net.Conn)
	rn.peers = make(map[int]net.Conn)
	rn.port = port
	rn.logger = logger
	rn.consumeCh = consumeCh
	rn.stopCh = stopCh
	rn.releaseCh = releaseCh
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
		go rn.handleConn(conn)
	}
}

// Shutdown network (local test.)
func (rn *Network) Shutdown() {
	close(rn.stopCh)
	rn.listener.Close()
	// Wait for all goroutine done (create by consensus module)
	<-rn.releaseCh
}

// Handle connection
func (rn *Network) handleConn(conn net.Conn) {
	defer func() {
		// delete connection from network and close connection.
		rn.logger.Printf("Remote machine [%s] close connection.\n", conn.RemoteAddr().String())
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

		// Catch stop signal
		select {
		case <-rn.stopCh:
			return
		default:
		}

		if req.NetworkMangeField != nil {
			rn.networkMange(req.NetworkMangeField, conn)
		}

		if req.ConsensusMsgField != nil {
			rn.consumeCh <- req.ConsensusMsgField
		}
	}
}

func (rn *Network) networkMange(msg *message.NetworkMange, connnectedConn net.Conn) {
	if msg.ConnPeerField != nil || msg.SetClientField != nil {
		rn.connect(msg, connnectedConn)
		return
	}

	if msg.DisConnPeerField != nil || msg.DisconnectClientField != nil {
		rn.disconnectPeer(msg)
		return
	}

	rn.logger.Printf("Unkonwn [%v] type of network manage.\n", msg)
}

// Connect to other network
func (rn *Network) connect(msg *message.NetworkMange, connectedConn net.Conn) {
	var op int
	var id int

	// Get operation type and remote connect identify
	if msg.ConnPeerField != nil {
		id = msg.ConnPeerField.PeerId
		op = PeerOP
	} else if msg.SetClientField != nil {
		id = msg.SetClientField.ClientId
		op = ClientOP
	} else {
		return
	}

	// If connected, return
	_, ok := rn.readMap(id, op)
	if ok {
		if op == PeerOP {
			rn.logger.Printf("[Peer:%d] has been connected.\n", id)
			return
		} else {
			rn.logger.Printf("[Client:%d] has been connected.\n", id)
			return
		}
	}

	// Create connection
	if op == PeerOP {
		conn, err := net.Dial("tcp", msg.ConnPeerField.PeerAddr)
		if err != nil {
			rn.logger.Printf("Connect to [Peer:%d] fail.\n", id)
			return
		}
		rn.writeMap(id, PeerOP, conn)
	}

	// Reuse connected connection
	if op == ClientOP {
		rn.writeMap(id, ClientOP, connectedConn)
	}
}

// Disconnect from other network
func (rn *Network) disconnectPeer(msg *message.NetworkMange) {
	var op int
	var id int

	if msg.DisConnPeerField != nil {
		op = PeerOP
		id = msg.DisConnPeerField.PeerId
	} else if msg.DisconnectClientField != nil {
		op = ClientOP
		id = msg.DisconnectClientField.ClientId
	} else {
		return
	}

	// Map delete is no-op if map is nil or key doesn't exist
	rn.deleteMap(id, op)
}

// Get data from map
func (rn *Network) readMap(id, op int) (net.Conn, bool) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	switch op {
	case PeerOP:
		if peer, ok := rn.peers[id]; ok {
			return peer, ok
		}
	case ClientOP:
		if client, ok := rn.clients[id]; ok {
			return client, ok
		}
	}
	return nil, false
}

// Set data to map
func (rn *Network) writeMap(id, op int, conn net.Conn) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	switch op {
	case PeerOP:
		rn.peers[id] = conn
	case ClientOP:
		rn.clients[id] = conn
	}
}

// Delete data from map
func (rn *Network) deleteMap(id, op int) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	// Close connection and delete connection from map
	switch op {
	case PeerOP:
		rn.peers[id].Close()
		delete(rn.peers, id)
	case ClientOP:
		rn.clients[id].Close()
		delete(rn.clients, id)
	}
}
