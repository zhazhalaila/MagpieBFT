package consensus

import (
	"encoding/json"
	"log"
	"strconv"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/libnet"
	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type NetworkMsg struct {
	// Write msg to network
	// Broadcast msg or send msg to peer
	broadcast bool
	peerId    int
	msg       message.ReqMsg
}

type ACSEvent struct {
	// Global channel to receive child module
	// Once child module done. e.g. rbc output | ba output ... notify acs
	// Common leader was elected from elect phase
	status       int
	instanceId   int
	rbcOut       []byte
	wprbcOut     message.PROOF
	pbOut        map[int]message.PROOF
	commonLeader int
	baOut        int
	baStop       bool
}

type ACS struct {
	// Global log
	logger *log.Logger
	// Network module
	network *libnet.Network
	// WaitGroup to wait for all created goroutine(write msg to network) done
	wg sync.WaitGroup
	n  int
	f  int
	id int
	// Current round
	// Epoch record run BA times
	round int
	epoch int
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// RBC and WPRBC outs
	// Seen proofs store received wprbc outs and pb req
	rbcOuts    map[int][]byte
	wprbcOuts  map[int]message.PROOF
	pbOuts     map[int]map[int]message.PROOF
	seenProofs map[int]message.PROOF
	// Txs channel to read txs from consensus module
	// ACS in channel to read data from consensus module
	// Output channel to consensus
	// Send clear signal to consensus
	// Network channel write data to network
	// Stop channel to exit acs
	// Done channel to notify consensus
	// Child Event channel to receive msg from child module
	// ACS output txs to consensus
	txsCh     chan [][]byte
	acsInCh   chan *message.ConsensusMsg
	acsOutCh  chan int
	acsClear  chan int
	networkCh chan NetworkMsg
	stopCh    chan bool
	doneCh    chan bool
	acsEvent  chan ACSEvent
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	wpInstances    []*WPRBC
	pbInstances    []*PB
	electInstances []*Elect
	abaInstances   []*ABA
}

func MakeAcs(logger *log.Logger,
	network *libnet.Network,
	n, f, id, round int,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
	acsOutCh, acsClear chan int) *ACS {
	acs := &ACS{}
	acs.logger = logger
	acs.network = network
	acs.n = n
	acs.f = f
	acs.id = id
	acs.round = round
	acs.epoch = 0
	acs.suite = suite
	acs.pubKey = pubKey
	acs.priKey = priKey
	acs.rbcOuts = make(map[int][]byte)
	acs.wprbcOuts = make(map[int]message.PROOF)
	acs.pbOuts = make(map[int]map[int]message.PROOF)
	acs.seenProofs = make(map[int]message.PROOF)
	acs.txsCh = make(chan [][]byte, 10)
	acs.acsInCh = make(chan *message.ConsensusMsg, 100)
	acs.networkCh = make(chan NetworkMsg, 100)
	acs.stopCh = make(chan bool)
	acs.doneCh = make(chan bool)
	acs.acsEvent = make(chan ACSEvent, acs.n*acs.n)
	acs.acsOutCh = acsOutCh
	acs.acsClear = acsClear
	acs.wpInstances = make([]*WPRBC, acs.n)
	acs.pbInstances = make([]*PB, acs.n)
	acs.electInstances = make([]*Elect, acs.n)
	acs.abaInstances = make([]*ABA, acs.n)

	// Init child instances
	for i := 0; i < acs.n; i++ {
		acs.wpInstances[i] = MakeWprbc(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
		acs.pbInstances[i] = MakePB(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
		acs.electInstances[i] = MakeElect(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
		acs.abaInstances[i] = MakeABA(acs.logger, acs.n, acs.f, acs.id, i, acs.round,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
	}

	go acs.run()

	return acs
}

func (acs *ACS) run() {
L:
	for {
		select {
		case <-acs.stopCh:
			acs.stopAllInstances()
			break L
		case txs := <-acs.txsCh:
			acs.handleTxs(txs)
		case msg := <-acs.acsInCh:
			acs.handlemsg(msg)
		case event := <-acs.acsEvent:
			acs.eventHandler(event)
		case reqMsg := <-acs.networkCh:
			go acs.sendToNetwork(reqMsg)
		}
	}

	// Wait for all wprbc instances done
	for i := 0; i < acs.n; i++ {
		<-acs.wpInstances[i].Done()
		<-acs.pbInstances[i].Done()
		<-acs.electInstances[i].Done()
		<-acs.abaInstances[i].Done()
	}

	acs.logger.Printf("[Round:%d] ACS done.\n", acs.round)

	for i := 0; i < acs.n; i++ {
		acs.wpInstances = nil
		acs.pbInstances = nil
		acs.electInstances = nil
		acs.abaInstances = nil
	}

	acs.logger.Printf("[Round:%d] ACS done.\n", acs.round)
	// ACS wait for all sub instances done, send a clear signal to consensus
	acs.acsClear <- acs.round
}

func (acs *ACS) stopAllInstances() {
	for i := 0; i < acs.n; i++ {
		acs.wpInstances[i].Stop()
		acs.pbInstances[i].Stop()
		acs.electInstances[i].Stop()
		acs.abaInstances[i].Stop()
	}
}

func (acs *ACS) handleTxs(txs [][]byte) {
	// Marshal
	txsBytes, err := json.Marshal(txs)
	if err != nil {
		acs.logger.Printf("[Round:%d] txs marshal failed.\n", acs.round)
		return
	}
	// Erasure code
	shards, err := ECEncode(acs.f+1, acs.n-(acs.f+1), txsBytes)
	if err != nil {
		acs.logger.Printf("[Round:%d] txs erasure code failed.\n", acs.round)
		return
	}
	// Merkle tree
	mt, err := merkletree.MakeMerkleTree(shards)
	if err != nil {
		acs.logger.Printf("[Round:%d] txs merkle tree failed.\n", acs.round)
		return
	}
	rootHash := mt[1]
	for i := 0; i < acs.n; i++ {
		branch := merkletree.GetMerkleBranch(i, mt)
		msg := message.GenWPRBCMsg(acs.id, acs.round, acs.id)
		msg.ConsensusMsgField.WprbcReqField.VALField = &message.VAL{
			RootHash: rootHash,
			Branch:   branch,
			Shard:    shards[i],
		}
		select {
		case <-acs.stopCh:
			return
		default:
			acs.networkCh <- NetworkMsg{broadcast: false, peerId: i, msg: msg}
		}
	}
}

func (acs *ACS) handlemsg(msg *message.ConsensusMsg) {
	if msg.WprbcReqField != nil {
		acs.wpInstances[msg.WprbcReqField.Proposer].InputValue(msg.WprbcReqField)
	}
	if msg.PBMsgField != nil {
		newMap := make(map[int]message.PROOF, acs.n)
		for k, v := range acs.seenProofs {
			newMap[k] = v
		}
		acs.pbInstances[msg.PBMsgField.Proposer].InputValue(newMap, msg.PBMsgField)
	}
	if msg.ElectMsgField != nil {
		acs.electInstances[msg.ElectMsgField.Epoch].InputValue(msg.ElectMsgField)
	}
	if msg.ABAMsgField != nil {
		acs.abaInstances[msg.ABAMsgField.InstanceId].InputValue(msg.ABAMsgField)
	}
}

func (acs *ACS) eventHandler(event ACSEvent) {
	switch event.status {
	case message.RBCOUTPUT:
		acs.rbcOuts[event.instanceId] = event.rbcOut
		acs.logger.Printf("[Round:%d] ACS deliver [%d] rbc instance.\n", acs.round, event.instanceId)
	case message.WPRBCOUTPUT:
		if _, ok := acs.wprbcOuts[event.instanceId]; ok {
			acs.logger.Printf("[Round:%d] ACS has delivered [%d] wprbc instance.\n", acs.round, event.instanceId)
			return
		}
		acs.wprbcOuts[event.instanceId] = event.wprbcOut
		if len(acs.wprbcOuts) == acs.n-acs.f {
			acs.pbThreshold()
		}
		if _, ok := acs.seenProofs[event.instanceId]; !ok {
			acs.seenProofs[event.instanceId] = event.wprbcOut
		}
		acs.logger.Printf("[Round:%d] ACS deliver [%d] wprbc instance.\n", acs.round, event.instanceId)
	case message.PBOUTPUT:
		if _, ok := acs.pbOuts[event.instanceId]; ok {
			acs.logger.Printf("[Round:%d] ACS has delivered [%d] pb instance.\n", acs.round, event.instanceId)
			return
		}
		acs.pbOuts[event.instanceId] = event.pbOut
		acs.logger.Printf("[Round:%d] ACS deliver [%d] pb instance.\n", acs.round, event.instanceId)
		if len(acs.pbOuts) == acs.n-acs.f {
			acs.electThreshold()
		}
	case message.ELECTOUTPUT:
		acs.logger.Printf("[Round:%d] ACS deliver [%d] elect instance.\n", acs.round, event.instanceId)
		if acs.id%2 == 0 {
			acs.abaInstances[0].InputEST(1)
		} else {
			acs.abaInstances[0].InputEST(0)
		}
	case message.BAOUTPUT:
		acs.logger.Printf("[Round:%d] [Epoch:%d] ACS receive %d from ABA.\n", acs.round, acs.epoch, event.baOut)
	case message.BASTOP:
		acs.logger.Printf("[Round:%d] stop ABA.\n", acs.round)
		select {
		case <-acs.stopCh:
			return
		default:
			acs.acsOutCh <- acs.round
		}
	}
}

// If delivered n-f wprbc instances, broadcast seen proofs
func (acs *ACS) pbThreshold() {
	proofBytes, err := json.Marshal(acs.wprbcOuts)
	if err != nil {
		acs.logger.Println(err)
		return
	}

	proofHash, err := verify.ConvertStructToHashBytes(proofBytes)
	if err != nil {
		acs.logger.Printf("[Round:%d] ACS hash n-f proofs fail.\n", acs.round)
		acs.logger.Println(err)
		return
	}

	pbReq := message.GenPBMsg(acs.round, acs.id)
	pbReq.ConsensusMsgField.PBMsgField.PBReqField = &message.PBReq{
		ProofHash: proofHash,
		Proofs:    proofBytes,
	}

	acs.logger.Printf("[Round:%d] start pb.\n", acs.round)

	reqMsg := NetworkMsg{broadcast: true, msg: pbReq}

	select {
	case <-acs.stopCh:
		return
	default:
		acs.networkCh <- reqMsg
	}
}

// If delivered n-f pb instances, broadcast elect share
func (acs *ACS) electThreshold() {
	electData := strconv.Itoa(acs.round) + "-" + strconv.Itoa(acs.epoch)
	electHash, err := verify.ConvertStructToHashBytes(electData)
	if err != nil {
		acs.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] generate elect hash failed.\n", acs.round, acs.epoch, acs.id)
		return
	}

	share, err := verify.GenShare(electHash, acs.suite, acs.priKey)
	if err != nil {
		acs.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] generate elect share failed.\n", acs.round, acs.epoch, acs.id)
		return
	}

	electMsg := message.GenElectMsg(acs.round, acs.epoch, acs.id)
	electMsg.ConsensusMsgField.ElectMsgField.ElectFileld = message.Elect{
		ElectHash: electHash,
		Share:     share,
	}

	reqMsg := NetworkMsg{broadcast: true, msg: electMsg}

	select {
	case <-acs.stopCh:
		return
	default:
		acs.networkCh <- reqMsg
	}
}

func (acs *ACS) sendToNetwork(reqMsg NetworkMsg) {
	if reqMsg.broadcast {
		acs.network.Broadcast(reqMsg.msg)
	} else {
		acs.network.SendToPeer(reqMsg.peerId, reqMsg.msg)
	}
}

// Send transactions to acs
func (acs *ACS) InputTxs(txs [][]byte) {
	acs.txsCh <- txs
}

// Send data to acs channel
func (acs *ACS) InputValue(msg *message.ConsensusMsg) {
	acs.acsInCh <- msg
}

// Close acs channel
func (acs *ACS) Stop() {
	close(acs.stopCh)
}

// Done channel
func (acs *ACS) Done() <-chan bool {
	return acs.doneCh
}
