package consensus

import (
	"log"
	"strconv"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/libnet"
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
	// ACS in channel to read data from consensus module
	// Output channel to consensus
	// Network channel write data to network
	// Stop channel to exit acs
	// Done channel to notify consensus
	// Child Event channel to receive msg from child module
	// ACS output txs to consensus
	acsInCh   chan *message.ConsensusMsg
	acsOutCh  chan [][]byte
	networkCh chan NetworkMsg
	stopCh    chan bool
	doneCh    chan bool
	acsEvent  chan ACSEvent
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	wpInstances    []*WPRBC
	pbInstances    []*PB
	electInstances []*Elect
}

func MakeAcs(logger *log.Logger,
	network *libnet.Network,
	n, f, id, round int,
	suite *bn256.Suite,
	pubKey *share.PubPoly,
	priKey *share.PriShare,
	acsOutCh chan [][]byte) *ACS {
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
	acs.acsInCh = make(chan *message.ConsensusMsg, 100)
	acs.networkCh = make(chan NetworkMsg, 100)
	acs.stopCh = make(chan bool)
	acs.doneCh = make(chan bool)
	acs.acsEvent = make(chan ACSEvent, 100)
	acs.acsOutCh = acsOutCh
	acs.wpInstances = make([]*WPRBC, acs.n)
	acs.pbInstances = make([]*PB, acs.n)
	acs.electInstances = make([]*Elect, acs.n)

	// Init child instances
	for i := 0; i < acs.n; i++ {
		acs.wpInstances[i] = MakeWprbc(acs.logger, i, acs.n, acs.f, acs.id, acs.round,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
		acs.pbInstances[i] = MakePB(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
			acs.suite, acs.pubKey, acs.priKey,
			acs.acsEvent, acs.networkCh)
		acs.electInstances[i] = MakeElect(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
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
		case msg := <-acs.acsInCh:
			acs.handlemsg(msg)
		case event := <-acs.acsEvent:
			acs.eventHandler(event)
		case reqMsg := <-acs.networkCh:
			acs.sendToNetwork(reqMsg)
		}
	}

	// Wait for all wprbc instances done
	for i := 0; i < len(acs.wpInstances); i++ {
		<-acs.wpInstances[i].Done()
	}

	acs.doneCh <- true
}

func (acs *ACS) stopAllInstances() {
	for i := 0; i < acs.n; i++ {
		acs.wpInstances[i].Stop()
		acs.pbInstances[i].Stop()
	}
}

func (acs *ACS) handlemsg(msg *message.ConsensusMsg) {
	if msg.WprbcReqField != nil {
		acs.wpInstances[msg.WprbcReqField.Proposer].InputValue(msg.WprbcReqField)
	}
	if msg.PBMsgField != nil {
		acs.pbInstances[msg.PBMsgField.Proposer].InputValue(acs.seenProofs, msg.PBMsgField)
	}
	if msg.ElectMsgField != nil {
		acs.electInstances[msg.ElectMsgField.Epoch].InputValue(msg.ElectMsgField)
	}
}

func (acs *ACS) eventHandler(event ACSEvent) {
	if event.status == message.RBCOUTPUT {
		acs.rbcOuts[event.instanceId] = event.rbcOut
		acs.logger.Printf("[Round:%d] ACS deliver [%d] rbc instance.\n", acs.round, event.instanceId)
	}

	if event.status == message.WPRBCOUTPUT {
		acs.wprbcOuts[event.instanceId] = event.wprbcOut
		if len(acs.wprbcOuts) == acs.n-acs.f {
			acs.pbThreshold()
		}
		if _, ok := acs.seenProofs[event.instanceId]; !ok {
			acs.seenProofs[event.instanceId] = event.wprbcOut
		}
		acs.logger.Printf("[Round:%d] ACS deliver [%d] wprbc instance.\n", acs.round, event.instanceId)
	}

	if event.status == message.PBOUTPUT {
		acs.pbOuts[event.instanceId] = event.pbOut
		acs.logger.Printf("[Round:%d] ACS deliver [%d] pb instance.\n", acs.round, event.instanceId)
		if len(acs.pbOuts) == acs.n-acs.f {
			acs.electThreshold()
		}
	}

	if event.status == message.ELECTOUTPUT {
		acs.logger.Printf("[Round:%d] [Epoch:%d] ACS deliver [%d] leader.\n", acs.round, acs.epoch, event.commonLeader)
	}
}

// If delivered n-f wprbc instances, broadcast seen proofs
func (acs *ACS) pbThreshold() {
	proofHash, err := verify.ConvertStructToHashBytes(acs.wprbcOuts)
	if err != nil {
		acs.logger.Printf("[Round:%d] ACS hash n-f proofs fail.\n", acs.round)
		acs.logger.Println(err)
		return
	}

	pbReq := message.GenPBMsg(acs.round, acs.id)
	pbReq.ConsensusMsgField.PBMsgField.PBReqField = &message.PBReq{
		ProofHash: proofHash,
		Proofs:    acs.wprbcOuts,
	}

	acs.logger.Printf("[Round:%d] start pb.\n", acs.round)

	reqMsg := NetworkMsg{broadcast: true, msg: pbReq}
	go acs.sendToNetwork(reqMsg)
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
	go acs.sendToNetwork(reqMsg)
}

func (acs *ACS) sendToNetwork(reqMsg NetworkMsg) {
	if reqMsg.broadcast {
		acs.network.Broadcast(reqMsg.msg)
	} else {
		acs.network.SendToPeer(reqMsg.peerId, reqMsg.msg)
	}
}

// Output data to consensus
func (acs *ACS) output(results [][]byte) {
	select {
	case <-acs.stopCh:
	default:
		acs.acsOutCh <- results
	}
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
