package libclient

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type RemotePeer struct {
	// Recode peer connection
	Conn     net.Conn
	Sender   *json.Encoder
	Receiver *json.Decoder
}

type Request struct {
	// Consensus time = startTime - endTime
	// ReplyPeers = f+1 response from consensus cluster
	StartTime  time.Time
	EndTime    time.Duration
	ReplyPeers []int
	Done       chan bool
}

type Client struct {
	// Mutex to prevent data race
	mu sync.Mutex
	n  int
	f  int
	// Client identify
	// Remote peer address
	id       int
	addrs    []string
	peers    map[int]RemotePeer
	requests map[int]Request
}

// Create new client
func NewClient(n, f, id int) *Client {
	c := &Client{}
	c.n = n
	c.f = f
	c.id = id
	c.addrs = make([]string, c.n)
	c.peers = make(map[int]RemotePeer)
	c.requests = make(map[int]Request)
	return c
}

func (c *Client) SendRequest() {
	txs := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		txs[i] = []byte("Hello")
	}

	fmt.Println(txs)

	req := message.ReqMsg{
		ConsensusMsgField: &message.ConsensusMsg{
			InputTxField: &message.InputTx{
				Transactions: txs,
			},
		},
	}

	c.sendMsg(c.peers[0].Sender, req)
}

// Read peer address
func (c *Client) ReadAddress(path string, n int) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		n--
		if n < 0 {
			break
		}
		lines = append(lines, scanner.Text())
	}

	if scanner.Err() != nil {
		log.Fatal(err)
	}

	c.addrs = lines
}

// Client connect peers
func (c *Client) ConnectRemotePeers() {
	for i := 0; i < c.n; i++ {
		// Create connection
		conn, err := net.Dial("tcp", c.addrs[i])
		if err != nil {
			log.Fatal(err)
		}
		c.peers[i] = RemotePeer{
			Conn:     conn,
			Sender:   json.NewEncoder(conn),
			Receiver: json.NewDecoder(conn),
		}
		// Construct client message
		msg := message.ReqMsg{
			NetworkMangeField: &message.NetworkMange{
				SetClientField: &message.SetClient{
					ClientId: c.id,
				},
			},
		}
		// Send client message
		c.sendMsg(c.peers[i].Sender, msg)
	}
}

// Peers connect Peers
func (c *Client) PeersConnectPeers() {
	for i := 0; i < c.n; i++ {
		for j := 0; j < c.n; j++ {
			connMsg := message.ReqMsg{
				NetworkMangeField: &message.NetworkMange{
					ConnPeerField: &message.ConnectPeer{
						PeerAddr: c.addrs[j],
						PeerId:   j,
					},
				},
			}
			c.sendMsg(c.peers[i].Sender, connMsg)
		}
	}
}

func (c *Client) sendMsg(sender *json.Encoder, msg message.ReqMsg) {
	err := sender.Encode(msg)
	if err != nil {
		log.Fatal(err)
	}
}
