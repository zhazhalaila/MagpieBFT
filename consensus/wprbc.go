package consensus

import (
	"fmt"
	"sync"

	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
)

type WPRBC struct {
	// Mutex to prevent data race
	mu sync.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Round (Create WPRBC instance round)
	// Echo threshold = OutputThreshold = 2f+1, Ready threshold = Erasure code threshold = f+1
	// From proposer (who propose value). From leader merkle tree root hash
	// Echo senders to prevent dedundant echo msg
	// Shares to store erasure code shares
	// Ready cache who has sent ready message to prevent redundant ready message
	// Only leader will receive shares from all peers
	// Leader will combine shares to signature
	n               int
	f               int
	id              int
	round           int
	echoThreshold   int
	readThreshold   int
	outputThreshold int
	readySent       bool
	fromProposer    int
	fromLeader      [32]byte
	echoSenders     map[int]int
	shards          map[[32]byte]map[int][]byte
	ready           map[[32]byte]map[int]int
	shares          map[int][]byte
	signature       []byte
	// WaitGroup to wait for all goroutine done
	// Wprbc channel to read data from acs
	// Stop channel exit wprbc
	// Event channel to nptify acs
	// Done channel to notify acs
	wg       sync.WaitGroup
	wprbcCh  chan *message.WprbcReq
	stopCh   chan bool
	acsEvent chan ACSEvent
	done     chan bool
}

func MakeWprbc(acsEvent chan ACSEvent) *WPRBC {
	wp := &WPRBC{}
	wp.readySent = false
	wp.echoSenders = make(map[int]int)
	wp.shards = make(map[[32]byte]map[int][]byte)
	wp.ready = make(map[[32]byte]map[int]int)
	wp.shares = make(map[int][]byte, 100)
	wp.wprbcCh = make(chan *message.WprbcReq, 100)
	wp.stopCh = make(chan bool)
	wp.acsEvent = acsEvent
	wp.done = make(chan bool)
	go wp.run()
	return wp
}

func (wp *WPRBC) run() {
L:
	for {
		select {
		case <-wp.stopCh:
			break L
		case msg := <-wp.wprbcCh:
			wp.wg.Add(1)
			go wp.outputRBC(msg)
		}
	}

	wp.wg.Wait()
	wp.done <- true
}

func (wp *WPRBC) handleVAL(val message.VAL, sender int) {
	if sender != wp.fromProposer {
		fmt.Printf("Get proposer = %d, Excepte = %d.\n", sender, wp.fromProposer)
		return
	}

	if merkletree.MerkleTreeVerify(val.Shard, val.RootHash, val.Branch, wp.id) {
		wp.fromLeader = val.RootHash
		// broadcast
	}
}

func (wp *WPRBC) handleECHO(echo message.ECHO, sender int) {
	wp.mu.Lock()
	defer wp.mu.Unlock()

	_, ok1 := wp.shards[echo.RootHash]
	_, ok2 := wp.shards[echo.RootHash][sender]
	_, ok3 := wp.echoSenders[sender]

	if (ok1 && ok2) || ok3 {
		fmt.Printf("Redundant echo msg from [%d].\n", sender)
		return
	}

	ok := merkletree.MerkleTreeVerify(echo.Shard, echo.RootHash, echo.Branch, sender)
	if ok {
		if _, ok := wp.shards[echo.RootHash]; !ok {
			wp.shards[echo.RootHash] = make(map[int][]byte)
		}
		wp.shards[echo.RootHash][sender] = echo.Shard
		wp.echoSenders[sender] = sender
	}

	if len(wp.shards[echo.RootHash]) >= wp.echoThreshold && !wp.readySent {
		wp.readySent = true
		// broadcast
	}

	if len(wp.ready[echo.RootHash]) >= wp.readThreshold && len(wp.shards[echo.RootHash]) >= wp.f+1 {
		// output
	}
}

func (wp *WPRBC) outputRBC(msg *message.WprbcReq) {
	defer func() {
		wp.wg.Done()
	}()

	if msg.Req%5 == 0 {
		select {
		case <-wp.stopCh:
			return
		case wp.acsEvent <- ACSEvent{status: message.RBCOUTPUT, leader: 2, rbcOut: []byte("hello")}:
		}
	}
}

// Send data to wprbc channel
func (wp *WPRBC) InputValue(msg *message.WprbcReq) {
	wp.wprbcCh <- msg
}

// Close wprbc channel
func (wp *WPRBC) Stop() {
	close(wp.stopCh)
}

// Done channel
func (wp *WPRBC) Done() <-chan bool {
	return wp.done
}
