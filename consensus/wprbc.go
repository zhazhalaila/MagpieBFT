package consensus

import (
	"fmt"
	"log"
	"sync"

	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type WPRBC struct {
	// Global log
	logger *log.Logger
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
	readyThreshold  int
	outputThreshold int
	valReceived     bool
	readySent       bool
	rbcOutputted    bool
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
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	wg        sync.WaitGroup
	wprbcCh   chan *message.WprbcReq
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
}

func MakeWprbc(logger *log.Logger,
	fromProposer, n, f, id, round int,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
	acsEvent chan ACSEvent,
	networkCh chan NetworkMsg) *WPRBC {
	wp := &WPRBC{}
	wp.logger = logger
	wp.n = n
	wp.f = f
	wp.id = id
	wp.round = round
	wp.suite = suite
	wp.pubKey = pubKey
	wp.priKey = priKey
	wp.readySent = false
	wp.rbcOutputted = false
	wp.fromProposer = fromProposer
	wp.echoThreshold = 2*f + 1
	wp.readyThreshold = f + 1
	wp.outputThreshold = 2*f + 1
	wp.valReceived = false
	wp.readySent = false
	wp.echoSenders = make(map[int]int, wp.n)
	wp.shards = make(map[[32]byte]map[int][]byte)
	wp.readySets = make(map[[32]byte]map[int]int)
	wp.readySenders = make(map[int]int, wp.n)
	wp.shares = make(map[int][]byte, wp.n)
	wp.wprbcCh = make(chan *message.WprbcReq, wp.n)
	wp.stopCh = make(chan bool)
	wp.acsEvent = acsEvent
	wp.networkCh = networkCh
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
			go wp.handleMsg(msg)
		}
	}

	wp.wg.Wait()
	wp.done <- true
}

func (wp *WPRBC) handleMsg(msg *message.WprbcReq) {
	if msg.VALField != nil {
		wp.handleVAL(msg.VALField, msg.Sender)
	} else if msg.ECHOField != nil {
		wp.handleECHO(msg.ECHOField, msg.Sender)
	} else if msg.READYField != nil {
		wp.handleREADY(msg.READYField, msg.Sender)
	} else if msg.PartialShareField != nil {
		wp.handleShare(msg.PartialShareField, msg.Proposer, msg.Sender)
	} else if msg.PROOFField != nil {
		wp.handleProof(msg.PROOFField, msg.Sender)
	}
}

// Check VAL send from proposer not byzantine sender
// If valid send echo msg to acs output channel
func (wp *WPRBC) handleVAL(val *message.VAL, sender int) {
	defer wp.wg.Done()

	if sender != wp.fromProposer {
		wp.logger.Printf("[Instance:%d] Get proposer = %d, Want = %d.\n", wp.fromProposer, sender, wp.fromProposer)
		return
	}

	if merkletree.MerkleTreeVerify(val.Shard, val.RootHash, val.Branch, wp.id) && !wp.valReceived {
		// wp.logger.Printf("[%d] receive VAL from [%d].\n", wp.id, sender)
		wp.fromLeader = val.RootHash
		wp.valReceived = true

		echo := message.GenWPRBCMsg(wp.id, wp.round, wp.fromProposer)
		echo.ConsensusMsgField.WprbcReqField.ECHOField = &message.ECHO{
			RootHash: val.RootHash,
			Branch:   val.Branch,
			Shard:    val.Shard,
		}

		select {
		case <-wp.stopCh:
			return
		default:
			wp.networkCh <- NetworkMsg{broadcast: true, msg: echo}
		}
	}
}

// If receive redundant echo msg, return
// If receive 2f+1 echo msg and not send ready msg, send msg to acs output channel
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (wp *WPRBC) handleECHO(echo *message.ECHO, sender int) {
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

	if !ok {
		wp.logger.Printf("[%d] receive unvalid ECHO msg from [%d].\n", wp.id, sender)
		return
	}

	if _, ok := wp.shards[echo.RootHash]; !ok {
		wp.shards[echo.RootHash] = make(map[int][]byte, wp.n)
	}

	wp.shards[echo.RootHash][sender] = echo.Shard
	wp.echoSenders[sender] = sender

	// wp.logger.Printf("[Round:%d] [Instance:%d] [%d] receive ECHO msg from [%d].\n", wp.round, wp.fromProposer, wp.id, sender)

	if len(wp.shards[echo.RootHash]) >= wp.echoThreshold && !wp.readySent {
		wp.readySent = true
		wp.readyToNetChannel(echo.RootHash)
	}

	if len(wp.readySets[echo.RootHash]) >= wp.readyThreshold && len(wp.shards[echo.RootHash]) >= wp.f+1 && !wp.rbcOutputted {
		wp.rbcOutputted = true
		if echo.RootHash == wp.fromLeader {
			wp.rbcOutput(echo.RootHash)
		}
	}
}

// If receive redundant ready msg, return
// If receive f+1 ready msg and not send ready msg, broadcast ready msg
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (wp *WPRBC) handleREADY(ready *message.READY, sender int) {
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
		wp.readySets[ready.RootHash] = make(map[int]int, wp.n)
	}

	wp.readySets[ready.RootHash][sender] = sender
	wp.readySenders[sender] = sender

	// wp.logger.Printf("[Instance:%d] [%d] receive READY msg from [%d].\n", wp.fromProposer, wp.id, sender)

	if len(wp.readySets[ready.RootHash]) >= wp.readyThreshold && !wp.readySent {
		wp.readySent = true
		// broadcast ready
		wp.readyToNetChannel(ready.RootHash)
	}

	if len(wp.readySets[ready.RootHash]) >= wp.readyThreshold && len(wp.shards[ready.RootHash]) >= wp.f+1 && !wp.rbcOutputted {
		wp.rbcOutputted = true
		if ready.RootHash == wp.fromLeader {
			wp.rbcOutput(ready.RootHash)
		}
	}
}

// Only proposer do this
// If receive redundant share, return
// If receive 2f+1 valid shares, compute signature
func (wp *WPRBC) handleShare(share *message.PartialShare, proposer, sender int) {
	defer wp.wg.Done()

	if proposer != wp.fromProposer {
		wp.logger.Printf("Get proposer = %d, want %d.\n", proposer, wp.fromProposer)
	}

	err := verify.ShareVerify(share.RootHash[:], share.Share, wp.suite, wp.pubKey)
	if err != nil {
		wp.logger.Printf("Proposer [%d] receive invalid share from [%d].\n", wp.id, sender)
		wp.logger.Println(err)
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
		signature, err := verify.ComputeSignature(share.RootHash[:], wp.suite, shares, wp.pubKey, wp.n, wp.f+1)
		if err != nil {
			wp.logger.Println(err)
			return
		}
		proof := message.GenWPRBCMsg(wp.id, wp.round, wp.id)
		proof.ConsensusMsgField.WprbcReqField.PROOFField = &message.PROOF{
			Signature: signature,
			RootHash:  share.RootHash,
		}

		select {
		case <-wp.stopCh:
			return
		default:
			wp.networkCh <- NetworkMsg{broadcast: true, msg: proof}
		}
	} else {
		wp.mu.Unlock()
	}
}

// If receive valid proof, output to acs
func (wp *WPRBC) handleProof(proof *message.PROOF, sender int) {
	defer wp.wg.Done()

	if sender != wp.fromProposer {
		wp.logger.Printf("Get proposer = %d, Want = %d.\n", sender, wp.fromProposer)
		return
	}

	err := verify.SignatureVerify(proof.RootHash[:], proof.Signature, wp.suite, wp.pubKey)
	if err != nil {
		wp.logger.Printf("[Peer:%d] receive invalid signature from [%d].\n", wp.id, sender)
		wp.logger.Println(err)
		return
	}
	wp.mu.Lock()
	wp.signature = proof.Signature
	wp.mu.Unlock()

	// Out to acs
	select {
	case <-wp.stopCh:
		return
	default:
		wprbcOut := message.PROOF{
			RootHash:  proof.RootHash,
			Signature: wp.signature,
		}
		wp.acsEvent <- ACSEvent{status: message.WPRBCOUTPUT, instanceId: wp.fromProposer, wprbcOut: wprbcOut}
	}
}

// broadcast ready msg
func (wp *WPRBC) readyToNetChannel(rootHash [32]byte) {
	ready := message.GenWPRBCMsg(wp.id, wp.round, wp.fromProposer)
	ready.ConsensusMsgField.WprbcReqField.READYField = &message.READY{
		RootHash: rootHash,
	}

	select {
	case <-wp.stopCh:
		return
	default:
		wp.networkCh <- NetworkMsg{broadcast: true, msg: ready}
	}
}

func (wp *WPRBC) rbcOutput(rootHash [32]byte) {
	shards := make([][]byte, wp.n)
	for i, shard := range wp.shards[rootHash] {
		shards[i] = shard
	}
	decode, err := ECDecode(wp.f+1, wp.n-(wp.f+1), shards)
	if err != nil {
		wp.logger.Println(err)
		return
	}

	select {
	case <-wp.stopCh:
		return
	default:
		wp.acsEvent <- ACSEvent{status: message.RBCOUTPUT, instanceId: wp.fromProposer, rbcOut: decode}
	}

	// start a new goroutine to compute share
	wp.wg.Add(1)
	go func() {
		defer wp.wg.Done()

		share, err := verify.GenShare(rootHash[:], wp.suite, wp.priKey)
		if err != nil {
			wp.logger.Println(err)
			return
		}
		partialShare := message.GenWPRBCMsg(wp.id, wp.round, wp.fromProposer)
		partialShare.ConsensusMsgField.WprbcReqField.PartialShareField = &message.PartialShare{
			RootHash: rootHash,
			Share:    share,
		}

		select {
		case <-wp.stopCh:
			return
		default:
			wp.networkCh <- NetworkMsg{broadcast: false, peerId: wp.fromProposer, msg: partialShare}
		}
	}()
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
