package consensus

import (
	"crypto/sha256"
	"log"
	"strconv"
	"sync"
	"time"

	"github.com/sasha-s/go-deadlock"
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

type ABA struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu deadlock.Mutex
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
	estSent map[int]map[int]bool
	// Coin shares
	coinShare map[int]map[int][]byte
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// WaitGroup to wait for all goroutine done
	wg sync.WaitGroup
	// Event change channel
	binChs  []chan int
	auxChs  []chan struct{}
	confChs []chan struct{}
	coinChs []chan int
	// ABA wait for est value input
	// ABA channel to read data from acs
	// Stop channel exit aba
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	// Skip channel (long time no receive aba msg from other parties)
	estCh     chan int
	abaCh     chan *message.ABAMsg
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
	skip      chan bool
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
	aba.binValues = make(map[int][]int, 30)
	aba.estValues = make(map[int]map[int][]int, 30)
	aba.auxValues = make(map[int]map[int][]int, 30)
	aba.confValues = make(map[int]map[int][]int, 30)
	aba.estSent = make(map[int]map[int]bool, 30)

	aba.coinShare = make(map[int]map[int][]byte, 30)

	for i := 0; i < 30; i++ {
		aba.estValues[i] = make(map[int][]int, aba.n)
		aba.auxValues[i] = make(map[int][]int, aba.n)
		aba.confValues[i] = make(map[int][]int, aba.n)
		aba.estSent[i] = make(map[int]bool, 2)
		aba.coinShare[i] = make(map[int][]byte, aba.n)
	}

	aba.suite = suite
	aba.pubKey = pubKey
	aba.priKey = priKey

	aba.binChs = make([]chan int, 30)
	aba.auxChs = make([]chan struct{}, 30)
	aba.confChs = make([]chan struct{}, 30)
	aba.coinChs = make([]chan int, 30)

	for i := 0; i < 30; i++ {
		aba.binChs[i] = make(chan int, 2+1)
		aba.auxChs[i] = make(chan struct{}, aba.n*aba.n)
		aba.confChs[i] = make(chan struct{}, aba.n*aba.n)
		aba.coinChs[i] = make(chan int)
	}

	aba.estCh = make(chan int)
	aba.abaCh = make(chan *message.ABAMsg, aba.n)
	aba.stopCh = make(chan bool)
	aba.acsEvent = acsEvent
	aba.networkCh = networkCh
	aba.done = make(chan bool)
	aba.skip = make(chan bool)

	go aba.run()
	return aba
}

func (aba *ABA) run() {
L:
	for {
		select {
		case <-aba.stopCh:
			aba.logger.Printf("[Round:%d] [Instance:%d] ABA stop due to all done.\n", aba.round, aba.instanceId)
			break L
		case msg := <-aba.abaCh:
			aba.wg.Add(1)
			go aba.handleMsg(msg)
		case est := <-aba.estCh:
			aba.est = est
			aba.wg.Add(1)
			go aba.start(est)
		case <-time.After(2 * time.Minute):
			close(aba.skip)
			aba.logger.Printf("[Round:%d] [Instance:%d] ABA stop due to long time not see msg.\n", aba.round, aba.instanceId)
			break L
		}
	}

	aba.wg.Wait()
	aba.done <- true
}

func (aba *ABA) start(est int) {
	aba.mu.Lock()
	sent := aba.estSent[aba.subround][est]
	aba.mu.Unlock()

	defer func() {
		aba.wg.Done()
		aba.logger.Printf("[Round:%d] ABA exit.\n", aba.round)
		aba.acsEvent <- ACSEvent{status: message.BASTOP, baStop: true}
	}()

	if sent {
		aba.logger.Printf("[Round:%d] [Subround:0] [Peer:%d] has sent est.\n", aba.round, aba.id)
	} else {
		aba.sendESTToNetChannel(aba.subround, est)
	}

	for {
		select {
		case <-aba.skip:
			aba.logger.Printf("[Round:%d] [Subround:%d] long time not see est, i should exit.\n", aba.round, aba.subround)
			return
		case w := <-aba.binChs[aba.subround]:
			// Broadcast w
			// aba.logger.Printf("[Round:%d] [Subround:%d] ABA receive bin value = %d.\n", aba.round, aba.subround, w)
			aba.sendAUXToNetChannel(aba.subround, w)
		}
	AuxLoop:
		// Wait for aux values not none
		for {
			select {
			case <-aba.skip:
				aba.logger.Printf("[Round:%d] [Subround:%d] long time not see aux, i should exit.\n", aba.round, aba.subround)
				return
			case <-aba.auxChs[aba.subround]:
				ok := aba.auxEvent(aba.subround)
				if ok {
					break AuxLoop
				}
			}
		}
		// aba.logger.Printf("[Round:%d] [Subround:%d] ABA (aux) decide.\n", aba.round, aba.subround)
		// Wait for conf values
		var values int
	ConfLoop:
		for {
			select {
			case <-aba.skip:
				aba.logger.Printf("[Round:%d] [Subround:%d] long time not see conf, i should exit.\n", aba.round, aba.subround)
				return
			case <-aba.confChs[aba.subround]:
				v, ok := aba.confEvent(aba.subround)
				if ok {
					values = v
					break ConfLoop
				}
			}
		}
		// aba.logger.Printf("[Round:%d] [Subround:%d] ABA (conf) value decide.\n", aba.round, aba.subround)
		var coin int
		select {
		case <-aba.skip:
			aba.logger.Printf("[Round:%d] [Subround:%d] long time not see coin, i should exit.\n", aba.round, aba.subround)
			return
		default:
			coin = <-aba.coinChs[aba.subround]
		}
		aba.logger.Printf("[Round:%d] [Subround:%d] ABA values=%d coin=%d.\n", aba.round, aba.subround, values, coin)
		stop := aba.setNewEst(values, coin)
		if stop {
			break
		} else {
			aba.subround++
			aba.sendESTToNetChannel(aba.subround, aba.est)
			aba.logger.Printf("[Round:%d] [Subround:%d] ABA move to next round est = %d.\n", aba.round, aba.subround, aba.est)
		}
	}
}

func (aba *ABA) auxEvent(subround int) bool {
	aba.mu.Lock()
	// If receive >=2f+1 aux msg with 1, broadacast 1.
	if inSlice(1, aba.binValues[subround]) && len(aba.auxValues[subround][1]) >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCONFToNetChannel(subround, 1)
		return true
	}

	// If receive >=2f+1 aux msg with 0, broadcast 0.
	if inSlice(0, aba.binValues[subround]) && len(aba.auxValues[subround][0]) >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCONFToNetChannel(subround, 0)
		return true
	}

	// If receive >=2f+1 aux msg with 0 & 1, broadcast (0,1)
	count := 0
	for _, v := range aba.binValues[subround] {
		count += len(aba.auxValues[subround][v])
	}
	if count >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCONFToNetChannel(subround, Both)
		return true
	}

	aba.mu.Unlock()
	return false
}

func (aba *ABA) confEvent(subround int) (int, bool) {
	aba.mu.Lock()
	// If receive == 2f+1 conf msg with 1, set value to 1 for current subround
	if inSlice(1, aba.binValues[subround]) && len(aba.confValues[subround][1]) >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCOINToNetChannel(subround)
		return 1, true
	}

	// If receive == 2f+1 conf msg with 0, set value to 0 for current subround
	if inSlice(0, aba.binValues[subround]) && len(aba.confValues[subround][0]) >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCOINToNetChannel(subround)
		return 0, true
	}

	// If receive >= 2f+1 conf msg
	// len(conf[0]) + len(conf[1]) + len(conf[(0, 1)]) >= 2f+1, set value to 2
	// len(conf[0]) + len(conf[1]) || len(conf[0]) + len(conf[(0,1)]) || len(conf[1]) + len(conf[(0,1)])
	count := 0

	if len(aba.binValues[subround]) == 2 {
		count += len(aba.confValues[subround][Both])
		count += len(aba.confValues[subround][0])
		count += len(aba.confValues[subround][1])
	}

	if count >= aba.n-aba.f {
		aba.mu.Unlock()
		aba.sendCOINToNetChannel(subround)
		return Both, true
	}

	aba.mu.Unlock()
	return -1, false
}

func (aba *ABA) setNewEst(values int, coin int) bool {
	stop := false
	if values != Both {
		if values == coin {
			if aba.alreadyDecide == nil {
				aba.alreadyDecide = &values
				select {
				case <-aba.stopCh:
					return stop
				default:
					aba.acsEvent <- ACSEvent{status: message.BAOUTPUT, instanceId: aba.instanceId, baOut: values}
				}
			} else if *aba.alreadyDecide == values {
				stop = true
			}
		}
		aba.est = values
	} else {
		aba.est = coin
	}
	return stop
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
			aba.binChs[subround] <- est.BinValue
			aba.auxChs[subround] <- struct{}{}
			aba.confChs[subround] <- struct{}{}
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
		aba.auxChs[subround] <- struct{}{}
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
		aba.confChs[subround] <- struct{}{}
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
			aba.coinChs[subround] <- int(coinHash[0]) % 2
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
