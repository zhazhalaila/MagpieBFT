package consensus

import (
	"encoding/json"
	"log"
	"strconv"

	"github.com/zhazhalaila/BFTProtocol/libnet"
	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type NetworkMsg struct {
	// Write msg to network
	// Broadcast msg or send msg to peer or send response to client
	broadcast bool
	peerId    int
	msg       message.ReqMsg
	clientRes bool
	res       message.ClientRes
}

type ACSEvent struct {
	// Global channel to receive child module
	// Once child module done. e.g. rbc output | ba output ... notify acs
	// Common leader was elected from elect phase
	status       int
	instanceId   int
	epoch        int
	rbcOut       []byte
	pcbcOut      message.PROOF
	pbOut        map[int]message.PROOF
	commonLeader int
	baOut        int
	baStop       bool
	decide       []int
}

type ACS struct {
	// Global log
	logger *log.Logger
	// Network module
	network *libnet.Network
	// N=3F+1
	n  int
	f  int
	id int
	// Current round
	// ElectTimes record run BA times
	// Current leader
	// Client ID
	// Client Request Count
	round      int
	electTimes int
	currLeader int
	clientId   int
	reqCount   int
	// RBC instance should be committed
	// If receive all rbc instance and aba stop exit acs instance
	// Only exit once to avoid channel error
	rbcsCommit []int
	recvAllRBC bool
	abaStop    bool
	exitted    bool
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
	txsCh     chan *message.InputTx
	acsInCh   chan *message.ConsensusMsg
	acsOutCh  chan int
	acsClear  chan int
	networkCh chan NetworkMsg
	stopCh    chan bool
	doneCh    chan bool
	acsEvent  chan ACSEvent
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	pcInstances    []*PCBC
	pbInstances    []*PB
	electInstances []*Elect
	abaInstances   []*ABA
	decideInstance *Decide
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
	acs.electTimes = 0
	acs.suite = suite
	acs.pubKey = pubKey
	acs.priKey = priKey
	acs.rbcOuts = make(map[int][]byte)
	acs.wprbcOuts = make(map[int]message.PROOF)
	acs.pbOuts = make(map[int]map[int]message.PROOF)
	acs.seenProofs = make(map[int]message.PROOF)
	acs.txsCh = make(chan *message.InputTx, 10)
	acs.acsInCh = make(chan *message.ConsensusMsg, 100)
	acs.networkCh = make(chan NetworkMsg, 100)
	acs.stopCh = make(chan bool)
	acs.doneCh = make(chan bool)
	acs.acsEvent = make(chan ACSEvent, acs.n*acs.n)
	acs.acsOutCh = acsOutCh
	acs.acsClear = acsClear
	acs.pcInstances = make([]*PCBC, acs.n)
	acs.pbInstances = make([]*PB, acs.n)
	acs.electInstances = make([]*Elect, acs.n)
	acs.abaInstances = make([]*ABA, acs.n)

	// Init child instances
	for i := 0; i < acs.n; i++ {
		acs.pcInstances[i] = MakePCBC(acs.logger, acs.n, acs.f, acs.id, acs.round, i,
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
	acs.decideInstance = MakeDecide(acs.logger, acs.n, acs.f, acs.id, acs.round,
		acs.suite, acs.pubKey,
		acs.acsEvent)

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

	// Wait for all child instances done
	for i := 0; i < acs.n; i++ {
		<-acs.pcInstances[i].Done()
		<-acs.pbInstances[i].Done()
		<-acs.electInstances[i].Done()
		<-acs.abaInstances[i].Done()
		acs.logger.Printf("[Round:%d] ACS receive [InstanceId:%d] ABA.\n", acs.round, i)
	}

	<-acs.decideInstance.Done()

	acs.logger.Printf("[Round:%d] ACS done.\n", acs.round)

	for i := 0; i < acs.n; i++ {
		acs.pcInstances = nil
		acs.pbInstances = nil
		acs.electInstances = nil
		acs.abaInstances = nil
	}
	acs.decideInstance = nil
	acs.logger.Printf("[Round:%d] ACS clear.\n", acs.round)
	// ACS wait for all sub instances done, send a clear signal to consensus
	acs.acsClear <- acs.round
	acs.logger.Printf("[Round:%d] acs exit.\n", acs.round)
}

func (acs *ACS) stopAllInstances() {
	for i := 0; i < acs.n; i++ {
		acs.pcInstances[i].Stop()
		acs.pbInstances[i].Stop()
		acs.electInstances[i].Stop()
		acs.abaInstances[i].Stop()
	}
	acs.decideInstance.Stop()
	acs.logger.Printf("[Round:%d] stop all instance.\n", acs.round)
}

func (acs *ACS) handleTxs(txMsg *message.InputTx) {
	// Marshal
	txsBytes, err := json.Marshal(txMsg.Transactions)
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
	// Assign client id and client request count
	acs.clientId = txMsg.ClientId
	acs.reqCount = txMsg.ReqCount
	for i := 0; i < acs.n; i++ {
		branch := merkletree.GetMerkleBranch(i, mt)
		msg := message.GenPCBCMsg(acs.id, acs.round, acs.id)
		msg.ConsensusMsgField.PCBCReqField.VALField = &message.VAL{
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
	if msg.PCBCReqField != nil {
		acs.pcInstances[msg.PCBCReqField.Proposer].InputValue(msg.PCBCReqField)
	}
	if msg.PBMsgField != nil {
		newMap := acs.mapCopy(acs.seenProofs)
		acs.pbInstances[msg.PBMsgField.Proposer].InputValue(newMap, msg.PBMsgField)
	}
	if msg.ElectMsgField != nil {
		acs.electInstances[msg.ElectMsgField.Epoch].InputValue(msg.ElectMsgField)
	}
	if msg.ABAMsgField != nil {
		acs.abaInstances[msg.ABAMsgField.InstanceId].InputValue(msg.ABAMsgField)
	}
	if msg.DecideMsgField != nil {
		newMap := acs.mapCopy(acs.seenProofs)
		acs.decideInstance.InputValue(newMap, msg.DecideMsgField)
	}
}

func (acs *ACS) mapCopy(origin map[int]message.PROOF) map[int]message.PROOF {
	newMap := make(map[int]message.PROOF, len(origin))
	for k, v := range origin {
		newMap[k] = v
	}
	return newMap
}

func (acs *ACS) eventHandler(event ACSEvent) {
	switch event.status {
	case message.RBCOUTPUT:
		acs.handleRBCOut(event.instanceId, event.rbcOut)
	case message.PCBCOUTPUT:
		acs.handlePCBCOut(event.instanceId, event.pcbcOut)
	case message.PBOUTPUT:
		acs.handlePBOut(event.instanceId, event.pbOut)
	case message.ELECTOUTPUT:
		acs.handleELECTOut(event.epoch, event.commonLeader)
	case message.BAOUTPUT:
		acs.handleBAOut(event.instanceId, event.baOut)
	case message.BASTOP:
		acs.handleBAStop(event.instanceId)
	case message.DECIDE:
		acs.handleDecide(event.decide)
	}
}

func (acs *ACS) handleRBCOut(instanceId int, rbcOut []byte) {
	acs.rbcOuts[instanceId] = rbcOut
	acs.logger.Printf("[Round:%d] ACS deliver [%d] rbc instance.\n", acs.round, instanceId)
	acs.logger.Printf("RBC output = %v.\n", rbcOut)

	if acs.recvAllRBC {
		return
	}

	recvAll := true
	for _, instanceId := range acs.rbcsCommit {
		if _, ok := acs.rbcOuts[instanceId]; !ok {
			recvAll = false
		}
	}

	if recvAll && acs.abaStop && !acs.exitted {
		acs.logger.Printf("[Round:%d] acs stop in rbc phase.\n", acs.round)
		acs.exitted = true
		select {
		case <-acs.stopCh:
			return
		default:
			res := message.ClientRes{Round: acs.round, ReqCount: acs.reqCount, PeerId: acs.id}
			acs.networkCh <- NetworkMsg{clientRes: true, res: res}
			acs.acsOutCh <- acs.round
		}
	}
}

func (acs *ACS) handlePCBCOut(instanceId int, proof message.PROOF) {
	// If received wprbc out, return
	if _, ok := acs.wprbcOuts[instanceId]; ok {
		acs.logger.Printf("[Round:%d] ACS has delivered [%d] pcbc instance.\n", acs.round, instanceId)
		return
	}
	acs.wprbcOuts[instanceId] = proof
	// If delivered n-f wprbc instances, participate elect
	if len(acs.wprbcOuts) == acs.n-acs.f {
		acs.pbThreshold()
	}
	// acs.logger.Printf("[Round:%d] ACS deliver [%d] wprbc instance.\n", acs.round, instanceId)
}

func (acs *ACS) handlePBOut(instanceId int, proofs map[int]message.PROOF) {
	if _, ok := acs.pbOuts[instanceId]; ok {
		// acs.logger.Printf("[Round:%d] ACS has delivered [%d] pb instance.\n", acs.round, instanceId)
		return
	}
	acs.pbOuts[instanceId] = proofs
	// acs.logger.Printf("[Round:%d] ACS deliver [%d] pb instance.\n", acs.round, instanceId)
	if len(acs.pbOuts) == acs.n-acs.f {
		acs.electThreshold()
	}
}

func (acs *ACS) handleELECTOut(epoch int, commonLeader int) {
	acs.logger.Printf("[Round:%d] ACS deliver [electTimes:%d] with [LeaderId:%d].\n", acs.round, epoch, commonLeader)
	acs.currLeader = commonLeader
	_, ok := acs.pbOuts[commonLeader]
	if ok {
		acs.abaInstances[epoch].InputEST(1)
	} else {
		acs.abaInstances[epoch].InputEST(0)
	}
}

func (acs *ACS) handleBAOut(instanceId, decide int) {
	acs.logger.Printf("[Round:%d] [electTimes:%d] ACS receive %d from [ABAInstance:%d].\n", acs.round, acs.electTimes, decide, instanceId)
	if decide != 1 {
		acs.electTimes++
		acs.electThreshold()
		return
	}

	notRecv := true
	if _, ok := acs.pbOuts[acs.currLeader]; ok {
		notRecv = false
	}
	acs.logger.Printf("[Round:%d] [electTimes:%d] not receive [CurrLeader:%d] ? %t.\n", acs.round, acs.electTimes, acs.currLeader, notRecv)

	decideMsg := message.GenDecideMsg(acs.round)
	decideMsg.ConsensusMsgField.DecideMsgField = &message.DecideMsg{}
	decideMsg.ConsensusMsgField.DecideMsgField.Leader = acs.currLeader
	decideMsg.ConsensusMsgField.DecideMsgField.Proposer = acs.id
	decideMsg.ConsensusMsgField.DecideMsgField.NotRecv = notRecv

	var err error
	var proofsBytes []byte
	if !notRecv {
		proofsBytes, err = json.Marshal(acs.pbOuts[acs.currLeader])
		if err != nil {
			acs.logger.Printf("[Round:%d] ACS marshal W_L error.\n", acs.round)
			acs.logger.Println(err)
			return
		}
	}
	decideMsg.ConsensusMsgField.DecideMsgField.Proofs = proofsBytes
	reqMsg := NetworkMsg{broadcast: true, msg: decideMsg}

	select {
	case <-acs.stopCh:
		return
	default:
		acs.networkCh <- reqMsg
	}
}

func (acs *ACS) handleBAStop(instanceId int) {
	acs.logger.Printf("[Round:%d] [epoch:%d] aba stop.\n", acs.round, instanceId)
	if instanceId >= acs.electTimes {
		acs.abaStop = true
	}
	acs.logger.Printf("[Round:%d] [epoch:%d] [electTimes:%d].\n", acs.round, instanceId, acs.electTimes)
	acs.logger.Printf("[Round:%d] receive all rbc instance ? %t.\n", acs.round, acs.recvAllRBC)

	if acs.abaStop && acs.recvAllRBC && !acs.exitted {
		acs.logger.Printf("[Round:%d] acs stop in aba phase.\n", acs.round)
		acs.exitted = true
		select {
		case <-acs.stopCh:
			return
		default:
			res := message.ClientRes{Round: acs.round, PeerId: acs.id, ReqCount: acs.reqCount}
			acs.networkCh <- NetworkMsg{clientRes: true, res: res}
			acs.acsOutCh <- acs.round
		}
	}
}

func (acs *ACS) handleDecide(decide []int) {
	acs.logger.Printf("[Round:%d] decide rbc instance = %v.\n", acs.round, decide)
	received := make([]int, 0)
	for instanceId := range acs.rbcOuts {
		received = append(received, instanceId)
	}
	acs.logger.Printf("[Round:%d] received rbc instance = %v.\n", acs.round, received)

	recvAll := true
	for _, instanceId := range decide {
		if _, ok := acs.rbcOuts[instanceId]; !ok {
			recvAll = false
		}
	}

	acs.logger.Printf("[Round:%d] handle decide receive all rbc instance ? %t.\n", acs.round, recvAll)

	acs.recvAllRBC = recvAll
	// If receive all rbc instances && aba stopped && acs not exit
	if recvAll && acs.abaStop && !acs.exitted {
		acs.logger.Printf("[Round:%d] acs stop in decide phase.\n", acs.round)
		acs.exitted = true
		select {
		case <-acs.stopCh:
			return
		default:
			res := message.ClientRes{Round: acs.round, PeerId: acs.id}
			acs.networkCh <- NetworkMsg{clientRes: true, res: res}
			acs.acsOutCh <- acs.round
		}
	} else {
		acs.rbcsCommit = decide
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
	electData := strconv.Itoa(acs.round) + "-" + strconv.Itoa(acs.electTimes)
	electHash, err := verify.ConvertStructToHashBytes(electData)
	if err != nil {
		acs.logger.Printf("[Round:%d] [electTimes:%d] [Peer:%d] generate elect hash failed.\n", acs.round, acs.electTimes, acs.id)
		return
	}

	share, err := verify.GenShare(electHash, acs.suite, acs.priKey)
	if err != nil {
		acs.logger.Printf("[Round:%d] [electTimes:%d] [Peer:%d] generate elect share failed.\n", acs.round, acs.electTimes, acs.id)
		return
	}

	electMsg := message.GenElectMsg(acs.round, acs.electTimes, acs.id)
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
	if reqMsg.clientRes {
		acs.network.ClientResponse(acs.clientId, reqMsg.res)
		return
	}

	if reqMsg.broadcast {
		acs.network.Broadcast(reqMsg.msg)
	} else {
		acs.network.SendToPeer(reqMsg.peerId, reqMsg.msg)
	}
}

// Send transactions to acs
func (acs *ACS) InputTxs(txMsg *message.InputTx) {
	acs.txsCh <- txMsg
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
