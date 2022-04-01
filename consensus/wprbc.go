package consensus

import (
	"fmt"
	"sync"

	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
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
	readySets       map[[32]byte]map[int]int
	readySenders    map[int]int
	shares          map[int][]byte
	signature       []byte
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// WaitGroup to wait for all goroutine done
	// Wprbc channel to read data from acs
	// Stop channel exit wprbc
	// Event channel to nptify acs
	// Send data to ACS out channel
	// Done channel to notify acs
	wg       sync.WaitGroup
	wprbcCh  chan *message.WprbcReq
	stopCh   chan bool
	acsEvent chan ACSEvent
	acsOut   chan ACSOut
	done     chan bool
}

func MakeWprbc(acsEvent chan ACSEvent, acsOut chan ACSOut) *WPRBC {
	wp := &WPRBC{}
	wp.readySent = false
	wp.echoSenders = make(map[int]int, 100)
	wp.shards = make(map[[32]byte]map[int][]byte)
	wp.readySets = make(map[[32]byte]map[int]int)
	wp.readySenders = make(map[int]int, 100)
	wp.shares = make(map[int][]byte, 100)
	wp.wprbcCh = make(chan *message.WprbcReq, 100)
	wp.stopCh = make(chan bool)
	wp.acsEvent = acsEvent
	wp.acsOut = acsOut
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

// Check VAL send from proposer not byzantine sender
// If valid send echo msg to acs output channel
func (wp *WPRBC) handleVAL(val message.VAL, sender int) {
	defer wp.wg.Done()

	if sender != wp.fromProposer {
		fmt.Printf("Get proposer = %d, Excepte = %d.\n", sender, wp.fromProposer)
		return
	}

	if merkletree.MerkleTreeVerify(val.Shard, val.RootHash, val.Branch, wp.id) {
		wp.fromLeader = val.RootHash

		echo := message.GenWPRBCMsg(wp.id, wp.round, wp.fromProposer)
		echo.ConsensusMsgField.WprbcReqField.ECHOField = &message.ECHO{
			RootHash: val.RootHash,
			Branch:   val.Branch,
			Shard:    val.Shard,
		}

		select {
		case <-wp.stopCh:
			return
		case wp.acsOut <- ACSOut{broadcast: true, msg: echo}:
		}
	}
}

// If receive redundant echo msg, return
// If receive 2f+1 echo msg and not send ready msg, send msg to acs output channel
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (wp *WPRBC) handleECHO(echo message.ECHO, sender int) {
	defer wp.wg.Done()

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
			wp.shards[echo.RootHash] = make(map[int][]byte, 100)
		}
		wp.shards[echo.RootHash][sender] = echo.Shard
		wp.echoSenders[sender] = sender
	}

	if len(wp.shards[echo.RootHash]) >= wp.echoThreshold && !wp.readySent {
		wp.readySent = true
		// broadcast ready
		wp.bcReady(echo.RootHash)
	}

	if len(wp.readySets[echo.RootHash]) >= wp.readThreshold && len(wp.shards[echo.RootHash]) >= wp.f+1 {
		// output
	}
}

// If receive redundant ready msg, return
// If receive f+1 ready msg and not send ready msg, broadcast ready msg
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (wp *WPRBC) handleREADY(ready message.READY, sender int) {
	defer wp.wg.Done()

	wp.mu.Lock()
	defer wp.mu.Unlock()

	_, ok1 := wp.readySenders[sender]
	_, ok2 := wp.readySets[ready.RootHash][sender]

	if ok1 || ok2 {
		fmt.Printf("Redundant ready msg from [%d].\n", sender)
		return
	}

	if _, ok := wp.readySets[ready.RootHash]; !ok {
		wp.readySets[ready.RootHash] = make(map[int]int, 100)
	}

	wp.readySets[ready.RootHash][sender] = sender
	wp.readySenders[sender] = sender

	if len(wp.readySets[ready.RootHash]) >= wp.readThreshold && !wp.readySent {
		wp.readySent = true
		// broadcast ready
		wp.bcReady(ready.RootHash)
	}

	if len(wp.readySets[ready.RootHash]) >= wp.readThreshold && len(wp.shards[ready.RootHash]) >= wp.f+1 {
		// output
	}
}

// Only proposer do this
// If receive redundant share, return
// If receive 2f+1 valid shares, compute signature
func (wp *WPRBC) handleShare(share message.PartialShare, sender int) {
	defer wp.wg.Done()

	rootHashHash, err := verify.ConvertStructToHashBytes(share.RootHash)
	if err != nil {
		// log
		return
	}

	err = verify.ShareVerify(rootHashHash, share.Share, wp.suite, wp.pubKey)
	if err != nil {
		// log
		return
	}

	wp.mu.Lock()
	wp.shares[sender] = share.Share
	if len(wp.shares) == wp.outputThreshold {
		var shares [][]byte
		for _, share := range wp.shares {
			shares = append(shares, share)
		}
		wp.mu.Unlock()
		// Compute siganture
		_, err := verify.ComputeSignature(rootHashHash, wp.suite, shares, wp.pubKey, wp.n, wp.f)
		if err != nil {
			// log return
			return
		}
		// Broadcast signature
	} else {
		wp.mu.Unlock()
	}
}

// If receive valid proof, output to acs
func (wp *WPRBC) handleProof(proof message.PROOF, sender int) {
	defer wp.wg.Done()

	rootHashHash, err := verify.ConvertStructToHashBytes(proof.RootHash)
	if err != nil {
		// log
		return
	}
	err = verify.SignatureVerify(rootHashHash, proof.Signature, wp.suite, wp.pubKey)
	if err != nil {
		// log
		return
	}
	wp.mu.Lock()
	wp.signature = proof.Signature
	wp.mu.Unlock()

	// Output to acs
}

// broadcast ready msg
func (wp *WPRBC) bcReady(rootHash [32]byte) {
	ready := message.GenConsensusMsg(wp.id, wp.id)
	ready.ConsensusMsgField.WprbcReqField.READYField = &message.READY{
		RootHash: rootHash,
	}

	select {
	case <-wp.stopCh:
		return
	case wp.acsOut <- ACSOut{broadcast: true, msg: ready}:
	}
}

func (wp *WPRBC) outputRBC(msg *message.WprbcReq) {
	defer wp.wg.Done()

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
