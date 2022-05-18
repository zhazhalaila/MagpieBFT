package libclient

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type remotePeer struct {
	// Recode peer connection
	conn     net.Conn
	sender   *json.Encoder
	receiver *json.Decoder
}

type request struct {
	// Elapsed time = time.Now() - startTime
	// ReplyPeers = f+1 response from consensus cluster
	startTime   time.Time
	elapsedTime time.Duration
	replyPeers  []int
}

type Client struct {
	// Mutex to prevent data race
	mu sync.Mutex
	n  int
	f  int
	// Client identify
	// Request count
	// Batch size
	// Remote peer address
	id        int
	reqCount  int
	batchSize int
	addrs     []string
	peers     map[int]remotePeer
	reqs      map[int]*request
	waiter    chan int
	done      chan bool
}

// Create new client
func NewClient(n, f, id, reqCount, batchSize int) *Client {
	c := &Client{}
	c.n = n
	c.f = f
	c.id = id
	c.reqCount = reqCount
	c.batchSize = batchSize
	c.addrs = make([]string, c.n)
	c.peers = make(map[int]remotePeer)
	c.reqs = make(map[int]*request, reqCount)
	c.waiter = make(chan int, c.reqCount)
	c.done = make(chan bool)

	// Init req
	for i := 0; i < c.reqCount; i++ {
		c.reqs[i] = &request{}
		c.reqs[i].replyPeers = make([]int, 0)
	}

	go c.wait()
	return c
}

// Send txs to consensus node
func (c *Client) SendRequest() {
	for req := 0; req < c.reqCount; req++ {
		for i := 0; i < c.n; i++ {
			txs := message.FakeBatchTx(c.batchSize, c.id, c.reqCount, i)
			req := message.ReqMsg{
				ConsensusMsgField: &message.ConsensusMsg{
					InputTxField: &message.InputTx{
						Transactions: txs,
						ClientId:     c.id,
						ReqCount:     req,
					},
				},
			}
			log.Println(txs)
			c.sendMsg(c.peers[i].sender, req)
		}
		c.reqs[req].startTime = time.Now()
		time.Sleep(500 * time.Millisecond)
	}
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
		c.peers[i] = remotePeer{
			conn:     conn,
			sender:   json.NewEncoder(conn),
			receiver: json.NewDecoder(conn),
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
		c.sendMsg(c.peers[i].sender, msg)
	}
}

// Peers connect Peers
func (c *Client) PeersConnectPeers() {
	for i := 0; i < c.n; i++ {
		for j := 0; j < c.n; j++ {
			connMsg := message.GenNetMangeMsg()
			connMsg.NetworkMangeField.ConnPeerField = &message.ConnectPeer{
				PeerAddr: c.addrs[j],
				PeerId:   j,
			}
			c.sendMsg(c.peers[i].sender, connMsg)
		}
	}

	c.recvMsg()
}

func (c *Client) Done() <-chan bool {
	return c.done
}

// Compute latency
func (c *Client) ComputeLatency() {
	var totalTime int64
	for i := 0; i < c.reqCount; i++ {
		totalTime += c.reqs[i].elapsedTime.Milliseconds()
	}
	log.Printf("BFT protocol consensus [%d] times within [%d] milliseconds.\n", c.reqCount, totalTime)
	log.Printf("[N=%d, F=%d, BatchSize=%d] BFT protocol need [%d]milliseconds to consens for a request.\n",
		c.n, c.f, c.batchSize, totalTime/int64(c.reqCount))
}

// Disconnect from remote peer
func (c *Client) Disconnect() {
	for i := 0; i < c.n; i++ {
		disConnMsg := message.GenNetMangeMsg()
		disConnMsg.NetworkMangeField.DisconnectClientField = &message.DisconnectClient{
			ClientId: c.id,
		}
		c.sendMsg(c.peers[i].sender, disConnMsg)
	}

	for i := 0; i < c.n; i++ {
		c.peers[i].conn.Close()
	}
}

// Wait for all requests receive 2f+1 response.
func (c *Client) wait() {
	for i := 0; i < c.reqCount; i++ {
		<-c.waiter
	}
	c.done <- true
}

// Create goroutine to handle peers' response
func (c *Client) recvMsg() {
	for peerId := range c.peers {
		go func(peerId int) {
			defer func() {
				c.mu.Lock()
				delete(c.peers, peerId)
				log.Printf("[Peer:%d] close connection.\n", peerId)
				c.mu.Unlock()
			}()

			for {
				var resMsg message.ClientRes
				if err := c.peers[peerId].receiver.Decode(&resMsg); err == io.EOF {
					break
				} else if err != nil {
					log.Println(err)
					break
				}
				log.Printf("[{Round:%d} {ReqCount:%d}] receive [PeerId:%d] response.\n", resMsg.Round, resMsg.ReqCount, resMsg.PeerId)
				c.resHandler(resMsg.ReqCount, resMsg.PeerId)
			}
		}(peerId)
	}
}

// Using lock to prevent data race.
func (c *Client) resHandler(reqCount int, peerId int) {
	c.mu.Lock()
	c.reqs[reqCount].replyPeers = append(c.reqs[reqCount].replyPeers, peerId)
	if len(c.reqs[reqCount].replyPeers) == 2*c.f+1 {
		c.reqs[reqCount].elapsedTime = time.Since(c.reqs[reqCount].startTime)
		c.mu.Unlock()
		log.Println("Send channel")
		c.waiter <- reqCount
	} else {
		c.mu.Unlock()
	}
}

// Send message to remote peer.
func (c *Client) sendMsg(sender *json.Encoder, msg message.ReqMsg) {
	err := sender.Encode(msg)
	if err != nil {
		log.Fatal(err)
	}
}
