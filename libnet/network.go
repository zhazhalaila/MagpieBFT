package libnet

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/sasha-s/go-deadlock"
	"github.com/zhazhalaila/BFTProtocol/message"
)

// Peer contain net.Conn and a wrapper for net.Conn to write data
type peer struct {
	conn    net.Conn
	encoder *json.Encoder
}

// io.Reader wrapper to count receive bytes
type countRead struct {
	conn  net.Conn
	count int64
}

func (cr *countRead) Read(p []byte) (n int, err error) {
	n, err = cr.conn.Read(p)
	cr.count += int64(n)
	return
}

type Network struct {
	// RWMutex to prevent data race
	mu deadlock.RWMutex
	// Total read bytes
	// Record connected clients
	// Remote peers
	readBytes int64
	clients   map[int]net.Conn
	peers     map[int]peer
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
	rn.peers = make(map[int]peer)
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

	fmt.Printf("Read total [%d] bytes.\n", rn.readBytes)
	fmt.Printf("Read total [%f] MB.\n", float64(rn.readBytes)/(1<<20))
}

func (rn *Network) Broadcast(msg message.ReqMsg) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	for id, peer := range rn.peers {
		err := peer.encoder.Encode(msg)
		if err != nil {
			rn.logger.Printf("Send msg to [Peer:%d] error.\n", id)
		}
	}
}

func (rn *Network) SendToPeer(peerId int, msg message.ReqMsg) {
	rn.mu.RLock()
	defer rn.mu.RUnlock()

	peer, ok := rn.peers[peerId]
	if !ok {
		rn.logger.Printf("[Peer:%d] disconnect.\n", peerId)
		return
	}

	err := peer.encoder.Encode(msg)
	if err != nil {
		rn.logger.Printf("Send msg to [Peer:%d] error.\n", peerId)
		rn.logger.Printf(err.Error())
	}
}

func (rn *Network) ClientResponse(clientId int, msg message.ResMsg) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	client, ok := rn.clients[clientId]
	if !ok {
		rn.logger.Printf("[Client:%d] has been diconnected.\n", clientId)
		return
	}

	// Message marshal
	msgEncoded, err := json.Marshal(msg)
	if err != nil {
		rn.logger.Printf(err.Error())
		return
	}

	_, err = client.Write(msgEncoded)
	if err != nil {
		rn.logger.Printf("Send msg to [Client:%d] error.\n", clientId)
		rn.logger.Printf(err.Error())
	}
}

// Handle connection
func (rn *Network) handleConn(conn net.Conn) {
	// read count
	cr := &countRead{conn: conn, count: 0}
	reader := bufio.NewReader(cr)
	defer func() {
		// delete connection from network and close connection.
		rn.logger.Printf("Remote machine [%s] close connection.\n", conn.RemoteAddr().String())
		rn.mu.Lock()
		rn.readBytes += cr.count
		rn.mu.Unlock()
		conn.Close()
	}()

	dec := json.NewDecoder(reader)

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
	if msg.ConnPeerField != nil {
		rn.connectPeer(*msg.ConnPeerField)
		return
	}

	if msg.SetClientField != nil {
		rn.recordClient(*msg.SetClientField, connnectedConn)
		return
	}

	if msg.DisConnPeerField != nil {
		rn.disconnectPeer(*msg.DisConnPeerField)
		return
	}

	if msg.DisconnectClientField != nil {
		rn.deleteClient(*msg.DisconnectClientField)
		return
	}

	rn.logger.Printf("Unkonwn [%v] type of network manage.\n", msg)
}

func (rn *Network) connectPeer(peerInfo message.ConnectPeer) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	_, ok := rn.peers[peerInfo.PeerId]
	if ok {
		rn.logger.Printf("[Peer:%d] has been connected.\n", peerInfo.PeerId)
		return
	}

	conn, err := net.Dial("tcp", peerInfo.PeerAddr)
	if err != nil {
		rn.logger.Printf("Connect to [Peer:%d] fail.\n", peerInfo.PeerId)
		return
	} else {
		rn.logger.Printf("Connect to [Peer:%d] success.\n", peerInfo.PeerId)
	}

	rn.peers[peerInfo.PeerId] = peer{conn: conn, encoder: json.NewEncoder(conn)}
}

func (rn *Network) disconnectPeer(peerInfo message.DisConnectPeer) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	peer, ok := rn.peers[peerInfo.PeerId]
	if ok {
		peer.conn.Close()
	}
	delete(rn.peers, peerInfo.PeerId)
}

func (rn *Network) recordClient(clientInfo message.SetClient, connectedConn net.Conn) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	_, ok := rn.clients[clientInfo.ClientId]
	if ok {
		rn.logger.Printf("[Client:%d] has been connected.\n", clientInfo.ClientId)
		return
	} else {
		rn.logger.Printf("[Client:%d] set success.\n", clientInfo.ClientId)
	}

	rn.clients[clientInfo.ClientId] = connectedConn
}

func (rn *Network) deleteClient(clientInfo message.DisconnectClient) {
	rn.mu.Lock()
	defer rn.mu.Unlock()

	conn, ok := rn.clients[clientInfo.ClientId]
	if ok {
		conn.Close()
	}

	delete(rn.clients, clientInfo.ClientId)
}
