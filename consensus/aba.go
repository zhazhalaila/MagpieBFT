package consensus

import (
	"crypto/sha256"
	"log"
	"strconv"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

const (
	AddBinary  = iota
	AuxRecv    = iota
	ConfRecv   = iota
	CommonCoin = iota
	Both       = iota
)

type abaEvent struct {
	// ABA event type .e.g. add binary value ...
	// Record event happen in which subround
	// Output common coin
	eventType int
	subround  int
	coin      int
}

type ABA struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu sync.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Run which ABA instance
	// Round (Create PB instance round)
	// Sub round (One common coin maybe not enough)
	// If peer delivered common leader's pb instance, est = 1 otherwise est = 0
	// Wait for ABA inputted then handle signal
	n          int
	f          int
	id         int
	instanceId int
	round      int
	subround   int
	est        int
	// Already decided
	alreadyDecide *int
	// Receive est values
	binValues map[int][]int
	// Each epoch has two possible binary value
	estValues  map[int]map[int][]int
	auxValues  map[int]map[int][]int
	confValues map[int]map[int][]int
	// Sent status
	estSent  map[int]map[int]bool
	auxSent  map[int]map[int]bool
	confSent map[int]map[int]bool
	coinSent map[int]bool
	// Coin shares
	coinShare map[int]map[int][]byte
	// Values
	values map[int]int
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// WaitGroup to wait for all goroutine done
	wg sync.WaitGroup
	// abaSignal chan
	abaSignal chan abaEvent
	// ABA wait for est value input
	// ABA channel to read data from acs
	// Stop channel exit aba
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	estCh     chan int
	abaCh     chan *message.ABAMsg
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
}

// Worst case need to run four subrounds
// For each subround peer maybe receive f+1 (0) and f+1 (1)
func MakeABA(
	logger *log.Logger,
	n, f, id, instanceId, round int,
	suite *bn256.Suite, pubKey *share.PubPoly, priKey *share.PriShare,
	acsEvent chan ACSEvent, networkCh chan NetworkMsg,
) *ABA {
	aba := &ABA{}
	aba.logger = logger
	aba.n = n
	aba.f = f
	aba.id = id
	aba.instanceId = instanceId
	aba.round = round
	aba.subround = 0
	aba.binValues = make(map[int][]int, 4)
	aba.estValues = make(map[int]map[int][]int, 4)
	aba.auxValues = make(map[int]map[int][]int, 4)
	aba.confValues = make(map[int]map[int][]int, 4)
	aba.estSent = make(map[int]map[int]bool, 4)
	aba.auxSent = make(map[int]map[int]bool, 4)
	aba.confSent = make(map[int]map[int]bool, 4)
	aba.coinSent = make(map[int]bool, 4)
	aba.coinShare = make(map[int]map[int][]byte, 4)
	aba.values = make(map[int]int, 4)

	for i := 0; i < 5; i++ {
		aba.estValues[i] = make(map[int][]int, aba.n)
		aba.auxValues[i] = make(map[int][]int, aba.n)
		aba.confValues[i] = make(map[int][]int, aba.n)
		aba.estSent[i] = make(map[int]bool, 2)
		aba.auxSent[i] = make(map[int]bool, 2)
		aba.confSent[i] = make(map[int]bool, 3)
		aba.coinShare[i] = make(map[int][]byte, aba.n)
	}

	aba.suite = suite
	aba.pubKey = pubKey
	aba.priKey = priKey
	aba.abaSignal = make(chan abaEvent, 4*aba.n)
	aba.estCh = make(chan int)
	aba.abaCh = make(chan *message.ABAMsg, aba.n)
	aba.stopCh = make(chan bool)
	aba.acsEvent = acsEvent
	aba.networkCh = networkCh
	aba.done = make(chan bool)
	go aba.run()
	return aba
}

func (aba *ABA) run() {
L:
	for {
		select {
		case <-aba.stopCh:
			break L
		case msg := <-aba.abaCh:
			aba.wg.Add(1)
			go aba.handleMsg(msg)
		case est := <-aba.estCh:
			aba.est = est
			aba.wg.Add(1)
			go aba.start(est)
		}
	}

	aba.wg.Wait()
	aba.done <- true
}

func (aba *ABA) handleMsg(msg *message.ABAMsg) {
	defer aba.wg.Done()

	if msg.ESTField != nil {
		aba.handleEST(msg.ESTField, msg.SubRound, msg.Sender)
	}
	if msg.AUXField != nil {
		aba.handleAUX(msg.AUXField, msg.SubRound, msg.Sender)
	}
	if msg.CONFField != nil {
		aba.handleCONF(msg.CONFField, msg.SubRound, msg.Sender)
	}
	if msg.COINField != nil {
		aba.handleCOIN(msg.COINField, msg.SubRound, msg.Sender)
	}
}

func (aba *ABA) start(est int) {
	defer aba.wg.Done()

	aba.mu.Lock()
	_, ok := aba.estSent[aba.subround][est]
	subround := aba.subround
	aba.mu.Unlock()

	if ok {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] has sent est = %d.\n", aba.round, aba.subround, aba.id, est)
	} else {
		aba.sendESTToNetChannel(subround, est)
	}

	for {
		select {
		case <-aba.stopCh:
			return
		case e := <-aba.abaSignal:
			aba.wg.Add(1)
			go aba.eventHandler(e)
		}
	}
}

func (aba *ABA) eventHandler(event abaEvent) {
	defer aba.wg.Done()

	switch event.eventType {
	case AddBinary:
		aba.mu.Lock()
		aux := aba.binValues[event.subround][len(aba.binValues[event.subround])-1]
		aba.logger.Printf("[Round:%d] [Subround:%d] binary values = %v.\n", aba.round, event.subround, aba.binValues[event.subround])
		aba.mu.Unlock()
		aba.sendAUXToNetChannel(event.subround, aux)
	case AuxRecv:
		aba.confThreshold(event.subround)
	case ConfRecv:
		aba.coinThreshold(event.subround)
	case CommonCoin:
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] receive [%d] coin.\n", aba.round, event.subround, aba.id, event.coin)
		aba.setNetEst(event.subround, event.coin)
	}
}

func (aba *ABA) confThreshold(subround int) {
	aba.mu.Lock()
	// If receive >=2f+1 aux msg with 1, broadacast 1.
	if inSlice(1, aba.binValues[subround]) && len(aba.auxValues[subround][1]) >= aba.n-aba.f {
		if !aba.confSent[subround][1] {
			aba.confSent[subround][1] = true
			aba.mu.Unlock()
			aba.sendCONFToNetChannel(subround, 1)
			return
		} else {
			aba.mu.Unlock()
			return
		}
	}
	// If receive >=2f+1 aux msg with 0, broadcast 0.
	if inSlice(0, aba.binValues[subround]) && len(aba.auxValues[subround][0]) >= aba.n-aba.f {
		if !aba.confSent[subround][0] {
			aba.confSent[subround][0] = true
			aba.mu.Unlock()
			aba.sendCONFToNetChannel(subround, 0)
			return
		} else {
			aba.mu.Unlock()
			return
		}
	}
	// If receive >=2f+1 aux msg with 0 & 1, broadcast (0,1)
	count := 0
	for _, v := range aba.binValues[subround] {
		count += len(aba.auxValues[subround][v])
	}
	if count >= aba.n-aba.f {
		if !aba.confSent[subround][Both] {
			aba.confSent[subround][Both] = true
			aba.mu.Unlock()
			aba.sendCONFToNetChannel(subround, Both)
			return
		}
	}

	aba.mu.Unlock()
}

func (aba *ABA) coinThreshold(subround int) {
	aba.mu.Lock()
	// If receive == 2f+1 conf msg with 1, set value to 1 for current subround
	if inSlice(1, aba.binValues[subround]) && len(aba.confValues[subround][1]) == aba.n-aba.f {
		if !aba.coinSent[subround] {
			aba.coinSent[subround] = true
			aba.values[subround] = 1
			aba.mu.Unlock()
			aba.sendCOINToNetChannel(subround)
			return
		} else {
			aba.mu.Unlock()
			return
		}
	}
	// If receive == 2f+1 conf msg with 0, set value to 0 for current subround
	if inSlice(0, aba.binValues[subround]) && len(aba.confValues[subround][0]) == aba.n-aba.f {
		if !aba.coinSent[subround] {
			aba.coinSent[subround] = true
			aba.values[subround] = 0
			aba.mu.Unlock()
			aba.sendCOINToNetChannel(subround)
			return
		} else {
			aba.mu.Unlock()
			return
		}
	}

	// If receive >= 2f+1 conf msg
	// len(conf[0]) + len(conf[1]) + len(conf[(0, 1)]) >= 2f+1, set value to 2
	// len(conf[0]) + len(conf[1]) || len(conf[0]) + len(conf[(0,1)]) || len(conf[1]) + len(conf[(0,1)])
	count := 0
	for _, v := range aba.binValues[subround] {
		count += len(aba.confValues[v])
	}
	if len(aba.binValues[subround]) == 2 {
		count += len(aba.confValues[Both])
	}

	if count >= aba.n-aba.f {
		if !aba.coinSent[subround] {
			aba.coinSent[subround] = true
			aba.values[subround] = Both
			aba.mu.Unlock()
			aba.sendCOINToNetChannel(subround)
			return
		}
	}

	aba.mu.Unlock()
}

func (aba *ABA) setNetEst(subround, commonCoin int) {
	aba.mu.Lock()
	aba.logger.Printf("[Round:%d] [Subround:%d] aba values = %d coin = %d.\n", aba.round, subround, aba.values[subround], commonCoin)
	if aba.values[subround] == commonCoin {
		if aba.alreadyDecide == nil {
			value := aba.values[subround]
			aba.alreadyDecide = &value
			aba.mu.Unlock()
			select {
			case <-aba.stopCh:
				return
			default:
				aba.acsEvent <- ACSEvent{status: message.BAOUTPUT, baOut: value}
			}
		}
	} else {
		aba.mu.Unlock()
	}

	aba.mu.Lock()
	aba.subround++
	aba.est = aba.values[subround]
	// If ba decide {0, 1} in current epoch, change est to coin in the next epoch.
	if aba.values[subround] == Both {
		aba.est = commonCoin
	}
	newSubround := aba.subround
	newEst := aba.est
	aba.mu.Unlock()

	aba.logger.Printf("[Round:%d] [Subround:%d] move to next round.\n", aba.round, newSubround)

	aba.sendESTToNetChannel(newSubround, newEst)
}

func inSlice(s int, list []int) bool {
	for _, b := range list {
		if b == s {
			return true
		}
	}
	return false
}

func (aba *ABA) handleEST(est *message.EST, subround int, sender int) {
	aba.mu.Lock()
	ok := inSlice(sender, aba.estValues[subround][est.BinValue])
	if ok {
		aba.mu.Unlock()
		return
	}

	aba.estValues[subround][est.BinValue] = append(aba.estValues[subround][est.BinValue], sender)
	estCount := len(aba.estValues[subround][est.BinValue])
	estSent := aba.estSent[subround][est.BinValue]
	aba.mu.Unlock()

	if estCount == aba.f+1 && !estSent {
		aba.sendESTToNetChannel(subround, est.BinValue)
	}

	if estCount == 2*aba.f+1 {
		// binary value change.
		aba.mu.Lock()
		aba.binValues[subround] = append(aba.binValues[subround], est.BinValue)
		aba.mu.Unlock()
		select {
		case <-aba.stopCh:
			return
		default:
			aba.abaSignal <- abaEvent{eventType: AddBinary, subround: subround}
		}
	}
}

func (aba *ABA) handleAUX(aux *message.AUX, subround, sender int) {
	aba.mu.Lock()
	ok := inSlice(sender, aba.auxValues[subround][aux.Element])
	if ok {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] has receive aux from [%d].\n",
			aba.round, aba.subround, aba.id, sender)
		aba.mu.Unlock()
		return
	} else {
		aba.auxValues[subround][aux.Element] = append(aba.auxValues[subround][aux.Element], sender)
		aba.mu.Unlock()
	}

	select {
	case <-aba.stopCh:
		return
	default:
		aba.abaSignal <- abaEvent{eventType: AuxRecv, subround: subround}
	}
}

func (aba *ABA) handleCONF(conf *message.CONF, subround, sender int) {
	aba.mu.Lock()
	ok := inSlice(sender, aba.confValues[subround][conf.Value])
	if ok {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] has receive conf from [%d].\n",
			aba.round, aba.subround, aba.id, sender)
		aba.mu.Unlock()
		return
	} else {
		aba.confValues[subround][conf.Value] = append(aba.confValues[subround][conf.Value], sender)
		aba.mu.Unlock()
	}

	select {
	case <-aba.stopCh:
		return
	default:
		aba.abaSignal <- abaEvent{eventType: ConfRecv, subround: subround}
	}
}

func (aba *ABA) handleCOIN(coin *message.COIN, subround, sender int) {
	err := verify.ShareVerify(coin.HashMsg, coin.Share, aba.suite, aba.pubKey)
	if err != nil {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] receive invalid share from [%d].\n",
			aba.round, subround, aba.id, sender)
		return
	}

	aba.mu.Lock()
	if len(aba.coinShare[subround][sender]) > aba.f+1 {
		aba.mu.Unlock()
		return
	}

	if _, ok := aba.coinShare[subround][sender]; ok {
		aba.mu.Unlock()
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] receive redundant share from [%d].\n",
			aba.round, subround, aba.id, sender)
		return
	}

	aba.coinShare[subround][sender] = coin.Share

	if len(aba.coinShare[subround]) == aba.f+1 {
		var shares [][]byte
		for _, share := range aba.coinShare[subround] {
			shares = append(shares, share)
		}
		aba.mu.Unlock()
		// Compute signature
		signature, err := verify.ComputeSignature(coin.HashMsg, aba.suite, shares, aba.pubKey, aba.n, aba.f+1)
		if err != nil {
			aba.logger.Printf("[Round:%d] [SubRound:%d] [Peer:%d] compute signature fail.\n", aba.round, subround, aba.id)
			return
		}
		// Verify signature
		err = verify.SignatureVerify(coin.HashMsg, signature, aba.suite, aba.pubKey)
		if err != nil {
			aba.logger.Printf("[Round:%d] [SubRound:%d] [Peer:%d] verify signature fail.\n", aba.round, subround, aba.id)
			return
		}
		// Generate common coin
		coinHash := sha256.Sum256(signature)
		select {
		case <-aba.stopCh:
			return
		default:
			aba.abaSignal <- abaEvent{eventType: CommonCoin, subround: subround, coin: int(coinHash[0]) % 2}
		}
	} else {
		aba.mu.Unlock()
	}
}

func (aba *ABA) sendESTToNetChannel(subround, est int) {
	aba.mu.Lock()
	aba.estSent[subround][est] = true
	aba.mu.Unlock()

	abaEst := message.GenABAMsg(aba.round, aba.instanceId, subround, aba.id)
	abaEst.ConsensusMsgField.ABAMsgField.ESTField = &message.EST{
		BinValue: est,
	}

	select {
	case <-aba.stopCh:
		return
	default:
		aba.networkCh <- NetworkMsg{broadcast: true, msg: abaEst}
	}
}

func (aba *ABA) sendAUXToNetChannel(subround, aux int) {
	abaAux := message.GenABAMsg(aba.round, aba.instanceId, subround, aba.id)
	abaAux.ConsensusMsgField.ABAMsgField.AUXField = &message.AUX{
		Element: aux,
	}

	select {
	case <-aba.stopCh:
		return
	default:
		aba.networkCh <- NetworkMsg{broadcast: true, msg: abaAux}
	}
}

func (aba *ABA) sendCONFToNetChannel(subround, conf int) {
	abaConf := message.GenABAMsg(aba.round, aba.instanceId, subround, aba.id)
	abaConf.ConsensusMsgField.ABAMsgField.CONFField = &message.CONF{
		Value: conf,
	}

	aba.logger.Printf("[Round:%d] [Subround:%d] broadcast conf = %d.\n", aba.round, subround, conf)

	select {
	case <-aba.stopCh:
		return
	default:
		aba.networkCh <- NetworkMsg{broadcast: true, msg: abaConf}
	}
}

func (aba *ABA) sendCOINToNetChannel(subround int) {
	abaCoin := message.GenABAMsg(aba.round, aba.instanceId, subround, aba.id)
	coinHash, err := verify.ConvertStructToHashBytes(strconv.Itoa(aba.round) + "-" + strconv.Itoa(subround))
	if err != nil {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] ABA marshal failed.\n", aba.round, subround, aba.id)
		return
	}

	coinShare, err := verify.GenShare(coinHash, aba.suite, aba.priKey)
	if err != nil {
		aba.logger.Printf("[Round:%d] [Subround:%d] [Peer:%d] compute ABA coin failed.\n", aba.round, subround, aba.id)
		aba.logger.Println(err)
		return
	}
	abaCoin.ConsensusMsgField.ABAMsgField.COINField = &message.COIN{
		HashMsg: coinHash,
		Share:   coinShare,
	}

	select {
	case <-aba.stopCh:
		return
	default:
		aba.networkCh <- NetworkMsg{broadcast: true, msg: abaCoin}
	}
}

// Input binary value to aba instance
func (aba *ABA) InputEST(est int) {
	aba.estCh <- est
}

// Send data to aba channel
func (aba *ABA) InputValue(msg *message.ABAMsg) {
	aba.abaCh <- msg
}

// Close aba channel
func (aba *ABA) Stop() {
	close(aba.stopCh)
}

// Done channel
func (aba *ABA) Done() <-chan bool {
	return aba.done
}
