package consensus

import (
	"bytes"
	"encoding/json"
	"log"
	"sync"

	"github.com/sasha-s/go-deadlock"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type PBMsgWithSeenProofs struct {
	seenProofs map[int]message.PROOF
	pbMsg      *message.PBMsg
}

type PB struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu deadlock.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Round (Create PB instance round)
	// From proposer record who broadcast proofs
	// Proofs hash to valid ps.Endorser's response
	n            int
	f            int
	id           int
	round        int
	fromProposer int
	proofsHash   []byte
	shares       map[int][]byte
	proofs       map[int]message.PROOF
	signature    []byte
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// WaitGroup to wait for all goroutine done
	// PB channel to read data from acs
	// Stop channel exit pb
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	wg        sync.WaitGroup
	pbCh      chan PBMsgWithSeenProofs
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
}

func MakePB(logger *log.Logger,
	n, f, id, round, fromProposer int,
	suite *bn256.Suite, pubKey *share.PubPoly, priKey *share.PriShare,
	acsEvent chan ACSEvent, networkCh chan NetworkMsg,
) *PB {
	pb := &PB{}
	pb.logger = logger
	pb.n = n
	pb.f = f
	pb.id = id
	pb.round = round
	pb.fromProposer = fromProposer
	pb.shares = make(map[int][]byte)
	pb.proofs = make(map[int]message.PROOF)
	pb.suite = suite
	pb.pubKey = pubKey
	pb.priKey = priKey
	pb.pbCh = make(chan PBMsgWithSeenProofs, pb.n*pb.n)
	pb.stopCh = make(chan bool)
	pb.acsEvent = acsEvent
	pb.networkCh = networkCh
	pb.done = make(chan bool)
	go pb.run()
	return pb
}

func (pb *PB) run() {
L:
	for {
		select {
		case <-pb.stopCh:
			break L
		case msg := <-pb.pbCh:
			pb.wg.Add(1)
			go pb.handlePBMsg(msg)
		}
	}

	pb.wg.Wait()
	pb.done <- true
}

func (pb *PB) handlePBMsg(msg PBMsgWithSeenProofs) {
	if msg.pbMsg.PBReqField != nil {
		pb.handlePBReq(msg.seenProofs, msg.pbMsg.PBReqField, msg.pbMsg.Proposer)
	} else if msg.pbMsg.PBResField != nil {
		pb.handlePBRes(msg.pbMsg.PBResField)
	} else if msg.pbMsg.PBDoneField != nil {
		pb.handlePBDone(msg.pbMsg.PBDoneField, msg.pbMsg.Proposer)
	}
}

func (pb *PB) handlePBReq(seenProofs map[int]message.PROOF, pr *message.PBReq, proposer int) {
	defer pb.wg.Done()

	if proposer != pb.fromProposer {
		pb.logger.Printf("Get proposer = %d, Excepte = %d.\n", proposer, pb.fromProposer)
		return
	}

	var proofs map[int]message.PROOF
	err := json.Unmarshal(pr.Proofs, &proofs)
	if err != nil {
		pb.logger.Println(err)
		return
	}

	// If pr.Proofs and seenProofs have the same key but different value, return
	// If pr.Proofs contain a invalid proof, return
	for i, proof := range proofs {
		if seen, ok := seenProofs[i]; ok {
			if !bytes.Equal(proof.Signature, seen.Signature) {
				pb.logger.Printf("[Peer:%d] conflict [Proposer:%d] on [WPRBC:%d].\n", pb.id, proposer, i)
				return
			}
		}
		err := verify.SignatureVerify(proof.RootHash[:], proof.Signature, pb.suite, pb.pubKey)
		if err != nil {
			pb.logger.Printf("[Proposer:%d] received invalid proof with [WPRBC:%d].\n", proposer, i)
			pb.logger.Println(err)
			return
		}
	}

	pb.mu.Lock()
	pb.proofs = proofs
	pb.mu.Unlock()
	// Send response to proposer

	share, err := verify.GenShare(pr.ProofHash, pb.suite, pb.priKey)
	if err != nil {
		pb.logger.Printf("[Round:%d] [Peer:%d] compute share error.\n", pb.round, pb.id)
		return
	}

	// pb.logger.Printf("[Round:%d] [Peer:%d] vote to [Proposer:%d].\n", pb.round, pb.id, proposer)

	pbRes := message.GenPBMsg(pb.round, proposer)
	pbRes.ConsensusMsgField.PBMsgField.PBResField = &message.PBRes{
		Endorser:  pb.id,
		ProofHash: pr.ProofHash,
		Share:     share,
	}

	select {
	case <-pb.stopCh:
		return
	default:
		pb.networkCh <- NetworkMsg{broadcast: false, peerId: proposer, msg: pbRes}
	}
}

func (pb *PB) handlePBRes(ps *message.PBRes) {
	defer pb.wg.Done()

	pb.mu.Lock()
	if _, ok := pb.shares[ps.Endorser]; ok {
		pb.mu.Unlock()
		pb.logger.Printf("[Proposer:%d] receive redundant PBRes msg from [%d].\n", pb.id, ps.Endorser)
		return
	}
	pb.mu.Unlock()

	err := verify.ShareVerify(ps.ProofHash, ps.Share, pb.suite, pb.pubKey)
	if err != nil {
		pb.logger.Printf("[Proposer:%d] receive invalid share from [%d].\n", pb.id, ps.Endorser)
	}

	// pb.logger.Printf("[Round:%d] [Proposer:%d] receive vote from [Endorser:%d].\n", pb.round, pb.id, ps.Endorser)

	pb.mu.Lock()
	pb.shares[ps.Endorser] = ps.Share
	if len(pb.shares) == 2*pb.f+1 {
		var shares [][]byte
		for _, share := range pb.shares {
			shares = append(shares, share)
		}
		pb.mu.Unlock()
		// Compute siganture
		signature, err := verify.ComputeSignature(ps.ProofHash, pb.suite, shares, pb.pubKey, pb.n, pb.f+1)
		if err != nil {
			pb.logger.Printf("[Round:%d] [Proposer:%d] compute invalid signature.\n", pb.round, pb.id)
			pb.logger.Println(err)
			return
		}
		pbDone := message.GenPBMsg(pb.round, pb.fromProposer)
		pbDone.ConsensusMsgField.PBMsgField.PBDoneField = &message.PBDone{
			Signature: signature,
			ProofHash: ps.ProofHash,
		}
		// Send to network message channel
		select {
		case <-pb.stopCh:
			return
		default:
			pb.networkCh <- NetworkMsg{broadcast: true, msg: pbDone}
		}

	} else {
		pb.mu.Unlock()
	}
}

func (pb *PB) handlePBDone(pbDone *message.PBDone, proposer int) {
	defer pb.wg.Done()

	if proposer != pb.fromProposer {
		pb.logger.Printf("[Round:%d] Get proposer = %d, Excepte = %d.\n", pb.round, proposer, pb.fromProposer)
		return
	}

	err := verify.SignatureVerify(pbDone.ProofHash, pbDone.Signature, pb.suite, pb.pubKey)
	if err != nil {
		pb.logger.Printf("[Round:%d] [Peer:%d] receive invalid signature from [%d].\n", pb.round, pb.id, proposer)
		return
	}

	pb.mu.Lock()
	pb.signature = pbDone.Signature
	pb.mu.Unlock()

	// pb.logger.Printf("[Round:%d] [Peer:%d] receive signature from [Proposer:%d].\n", pb.round, pb.id, proposer)

	// Out to acs
	select {
	case <-pb.stopCh:
		return
	default:
		pb.acsEvent <- ACSEvent{status: message.PBOUTPUT, instanceId: pb.fromProposer, pbOut: pb.proofs}
	}
}

// Send data to pb
func (pb *PB) InputValue(seenProofs map[int]message.PROOF, msg *message.PBMsg) {
	pbWrapper := PBMsgWithSeenProofs{}
	if msg.PBReqField != nil {
		pbWrapper.seenProofs = seenProofs
	}
	pbWrapper.pbMsg = msg
	pb.pbCh <- pbWrapper
}

// Close pb channel
func (pb *PB) Stop() {
	close(pb.stopCh)
}

// Done channel
func (pb *PB) Done() <-chan bool {
	return pb.done
}
