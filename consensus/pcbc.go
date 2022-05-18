package consensus

import (
	"fmt"
	"log"
	"sync"

	"github.com/sasha-s/go-deadlock"
	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type PCBC struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu deadlock.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Round (Create PCBC instance round)
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
	// PCBC channel to read data from acs
	// Stop channel exit PCBC
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	wg        sync.WaitGroup
	PCBCCh    chan *message.PCBCReq
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
}

func MakePCBC(logger *log.Logger,
	n, f, id, round, fromProposer int,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
	acsEvent chan ACSEvent,
	networkCh chan NetworkMsg) *PCBC {
	pc := &PCBC{}
	pc.logger = logger
	pc.n = n
	pc.f = f
	pc.id = id
	pc.round = round
	pc.suite = suite
	pc.pubKey = pubKey
	pc.priKey = priKey
	pc.readySent = false
	pc.rbcOutputted = false
	pc.fromProposer = fromProposer
	pc.echoThreshold = 2*f + 1
	pc.readyThreshold = f + 1
	pc.outputThreshold = 2*f + 1
	pc.valReceived = false
	pc.readySent = false
	pc.echoSenders = make(map[int]int, pc.n)
	pc.shards = make(map[[32]byte]map[int][]byte)
	pc.readySets = make(map[[32]byte]map[int]int)
	pc.readySenders = make(map[int]int, pc.n)
	pc.shares = make(map[int][]byte, pc.n)
	pc.PCBCCh = make(chan *message.PCBCReq, pc.n)
	pc.stopCh = make(chan bool)
	pc.acsEvent = acsEvent
	pc.networkCh = networkCh
	pc.done = make(chan bool)
	go pc.run()
	return pc
}

// Start PCBC instance
func (pc *PCBC) run() {
L:
	for {
		select {
		case <-pc.stopCh:
			break L
		case msg := <-pc.PCBCCh:
			pc.wg.Add(1)
			go pc.handleMsg(msg)
		}
	}

	pc.wg.Wait()
	pc.done <- true
}

func (pc *PCBC) handleMsg(msg *message.PCBCReq) {
	if msg.VALField != nil {
		pc.handleVAL(msg.VALField, msg.Sender)
	} else if msg.ECHOField != nil {
		pc.handleECHO(msg.ECHOField, msg.Sender)
	} else if msg.READYField != nil {
		pc.handleREADY(msg.READYField, msg.Sender)
	} else if msg.PartialShareField != nil {
		pc.handleShare(msg.PartialShareField, msg.Proposer, msg.Sender)
	} else if msg.PROOFField != nil {
		pc.handleProof(msg.PROOFField, msg.Sender)
	}
}

// Check VAL send from proposer not byzantine sender
// If valid send echo msg to acs output channel
func (pc *PCBC) handleVAL(val *message.VAL, sender int) {
	defer pc.wg.Done()

	if sender != pc.fromProposer {
		pc.logger.Printf("[Instance:%d] Get proposer = %d, Want = %d.\n", pc.fromProposer, sender, pc.fromProposer)
		return
	}

	if merkletree.MerkleTreeVerify(val.Shard, val.RootHash, val.Branch, pc.id) && !pc.valReceived {
		// pc.logger.Printf("[%d] receive VAL from [%d].\n", pc.id, sender)
		pc.fromLeader = val.RootHash
		pc.valReceived = true

		echo := message.GenPCBCMsg(pc.id, pc.round, pc.fromProposer)
		echo.ConsensusMsgField.PCBCReqField.ECHOField = &message.ECHO{
			RootHash: val.RootHash,
			Branch:   val.Branch,
			Shard:    val.Shard,
		}

		select {
		case <-pc.stopCh:
			return
		default:
			pc.networkCh <- NetworkMsg{broadcast: true, msg: echo}
		}
	}
}

// If receive redundant echo msg, return
// If receive 2f+1 echo msg and not send ready msg, send msg to acs output channel
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (pc *PCBC) handleECHO(echo *message.ECHO, sender int) {
	defer pc.wg.Done()

	pc.mu.Lock()

	_, ok1 := pc.shards[echo.RootHash]
	_, ok2 := pc.shards[echo.RootHash][sender]
	_, ok3 := pc.echoSenders[sender]

	if (ok1 && ok2) || ok3 {
		pc.mu.Unlock()
		fmt.Printf("Redundant echo msg from [%d].\n", sender)
		return
	}

	ok := merkletree.MerkleTreeVerify(echo.Shard, echo.RootHash, echo.Branch, sender)

	if !ok {
		pc.mu.Unlock()
		pc.logger.Printf("[%d] receive unvalid ECHO msg from [%d].\n", pc.id, sender)
		return
	}

	if _, ok := pc.shards[echo.RootHash]; !ok {
		pc.shards[echo.RootHash] = make(map[int][]byte, pc.n)
	}

	pc.shards[echo.RootHash][sender] = echo.Shard
	pc.echoSenders[sender] = sender

	// pc.logger.Printf("[Round:%d] [RBC%d] instance receive echos from [%v].\n", pc.round, pc.fromProposer, pc.echoSenders)

	// pc.logger.Printf("[Round:%d] [Instance:%d] [%d] receive ECHO msg from [%d].\n", pc.round, pc.fromProposer, pc.id, sender)

	if len(pc.shards[echo.RootHash]) >= pc.echoThreshold && !pc.readySent {
		pc.readySent = true
		pc.mu.Unlock()
		pc.readyToNetChannel(echo.RootHash)
		return
	}

	if len(pc.readySets[echo.RootHash]) >= pc.outputThreshold && len(pc.shards[echo.RootHash]) >= pc.f+1 && !pc.rbcOutputted {
		pc.rbcOutputted = true
		pc.mu.Unlock()
		pc.rbcOutput(echo.RootHash)
		return
	}

	pc.mu.Unlock()
}

// If receive redundant ready msg, return
// If receive f+1 ready msg and not send ready msg, broadcast ready msg
// If receive 2f+1 ready msg and f+1 echo msg, output to acs
func (pc *PCBC) handleREADY(ready *message.READY, sender int) {
	defer pc.wg.Done()

	pc.mu.Lock()

	_, ok1 := pc.readySenders[sender]
	_, ok2 := pc.readySets[ready.RootHash][sender]

	if ok1 || ok2 {
		fmt.Printf("Redundant ready msg from [%d].\n", sender)
		pc.mu.Unlock()
		return
	}

	if _, ok := pc.readySets[ready.RootHash]; !ok {
		pc.readySets[ready.RootHash] = make(map[int]int, pc.n)
	}

	pc.readySets[ready.RootHash][sender] = sender
	pc.readySenders[sender] = sender

	// pc.logger.Printf("[Instance:%d] [%d] receive READY msg from [%d].\n", pc.fromProposer, pc.id, sender)

	if len(pc.readySets[ready.RootHash]) >= pc.readyThreshold && !pc.readySent {
		pc.readySent = true
		pc.mu.Unlock()
		// broadcast ready
		pc.readyToNetChannel(ready.RootHash)
		return
	}

	if len(pc.readySets[ready.RootHash]) >= pc.outputThreshold && len(pc.shards[ready.RootHash]) >= pc.f+1 && !pc.rbcOutputted {
		pc.rbcOutputted = true
		pc.mu.Unlock()
		pc.rbcOutput(ready.RootHash)
		return
	}

	pc.mu.Unlock()
}

// Only proposer do this
// If receive redundant share, return
// If receive 2f+1 valid shares, compute signature
func (pc *PCBC) handleShare(share *message.PartialShare, proposer, sender int) {
	defer pc.wg.Done()

	if proposer != pc.fromProposer {
		pc.logger.Printf("Get proposer = %d, want %d.\n", proposer, pc.fromProposer)
	}

	err := verify.ShareVerify(share.RootHash[:], share.Share, pc.suite, pc.pubKey)
	if err != nil {
		pc.logger.Printf("Proposer [%d] receive invalid share from [%d].\n", pc.id, sender)
		pc.logger.Println(err)
		return
	}

	pc.mu.Lock()
	pc.shares[sender] = share.Share
	if len(pc.shares) == pc.outputThreshold {
		var shares [][]byte
		for _, share := range pc.shares {
			shares = append(shares, share)
		}
		pc.mu.Unlock()
		// Compute siganture
		signature, err := verify.ComputeSignature(share.RootHash[:], pc.suite, shares, pc.pubKey, pc.n, pc.f+1)
		if err != nil {
			pc.logger.Println(err)
			return
		}
		proof := message.GenPCBCMsg(pc.id, pc.round, pc.id)
		proof.ConsensusMsgField.PCBCReqField.PROOFField = &message.PROOF{
			Signature: signature,
			RootHash:  share.RootHash,
		}

		select {
		case <-pc.stopCh:
			return
		default:
			pc.networkCh <- NetworkMsg{broadcast: true, msg: proof}
		}
	} else {
		pc.mu.Unlock()
	}
}

// If receive valid proof, output to acs
func (pc *PCBC) handleProof(proof *message.PROOF, sender int) {
	defer pc.wg.Done()

	if sender != pc.fromProposer {
		pc.logger.Printf("Get proposer = %d, Want = %d.\n", sender, pc.fromProposer)
		return
	}

	err := verify.SignatureVerify(proof.RootHash[:], proof.Signature, pc.suite, pc.pubKey)
	if err != nil {
		pc.logger.Printf("[Peer:%d] receive invalid signature from [%d].\n", pc.id, sender)
		pc.logger.Println(err)
		return
	}
	pc.mu.Lock()
	pc.signature = proof.Signature
	pc.mu.Unlock()

	// Out to acs
	select {
	case <-pc.stopCh:
		return
	default:
		pcbcOut := message.PROOF{
			RootHash:  proof.RootHash,
			Signature: pc.signature,
		}
		pc.acsEvent <- ACSEvent{status: message.PCBCOUTPUT, instanceId: pc.fromProposer, pcbcOut: pcbcOut}
	}
}

// broadcast ready msg
func (pc *PCBC) readyToNetChannel(rootHash [32]byte) {
	ready := message.GenPCBCMsg(pc.id, pc.round, pc.fromProposer)
	ready.ConsensusMsgField.PCBCReqField.READYField = &message.READY{
		RootHash: rootHash,
	}

	select {
	case <-pc.stopCh:
		return
	default:
		pc.networkCh <- NetworkMsg{broadcast: true, msg: ready}
	}
}

// rbc output with erasure code decode
func (pc *PCBC) rbcOutput(rootHash [32]byte) {
	shards := make([][]byte, pc.n)
	for i, shard := range pc.shards[rootHash] {
		shards[i] = shard
	}
	decode, err := ECDecode(pc.f+1, pc.n-(pc.f+1), shards)
	if err != nil {
		pc.logger.Println(err)
		return
	}

	select {
	case <-pc.stopCh:
		return
	default:
		pc.acsEvent <- ACSEvent{status: message.RBCOUTPUT, instanceId: pc.fromProposer, rbcOut: decode}
	}

	// start a new goroutine to compute share
	pc.wg.Add(1)
	go func() {
		defer pc.wg.Done()

		share, err := verify.GenShare(rootHash[:], pc.suite, pc.priKey)
		if err != nil {
			pc.logger.Println(err)
			return
		}
		partialShare := message.GenPCBCMsg(pc.id, pc.round, pc.fromProposer)
		partialShare.ConsensusMsgField.PCBCReqField.PartialShareField = &message.PartialShare{
			RootHash: rootHash,
			Share:    share,
		}

		select {
		case <-pc.stopCh:
			return
		default:
			pc.networkCh <- NetworkMsg{broadcast: false, peerId: pc.fromProposer, msg: partialShare}
		}
	}()
}

// Send data to PCBC channel
func (pc *PCBC) InputValue(msg *message.PCBCReq) {
	pc.PCBCCh <- msg
}

// Close PCBC channel
func (pc *PCBC) Stop() {
	close(pc.stopCh)
}

// Done channel
func (pc *PCBC) Done() <-chan bool {
	return pc.done
}
