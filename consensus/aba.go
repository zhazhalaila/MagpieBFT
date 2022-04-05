package consensus

import (
	"log"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

const (
	AddBinary = iota
	AuxRecv   = iota
	ConfRecv  = iota
	CoinRecv  = iota
	Both      = iota
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
	n          int
	f          int
	id         int
	instanceId int
	round      int
	subround   int
	est        int
	// Receive est values
	binValues map[int]int
	// Each epoch has two possible binary value
	estValues  map[int]map[int][]int
	auxValues  map[int]map[int][]int
	confValues map[int]map[int][]int
	// Sent status
	estSent  map[int]map[int]bool
	auxSent  map[int]map[int]bool
	confSent map[int]map[int]bool
	// Coin shares
	coinShare map[int]map[int][]byte
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
	aba.binValues = make(map[int]int, 4)
	aba.estValues = make(map[int]map[int][]int, 4)
	aba.auxValues = make(map[int]map[int][]int, 4)
	aba.confValues = make(map[int]map[int][]int, 4)
	aba.estSent = make(map[int]map[int]bool, 4)
	aba.auxSent = make(map[int]map[int]bool, 4)
	aba.confSent = make(map[int]map[int]bool, 4)
	aba.coinShare = make(map[int]map[int][]byte, 4)

	for i := 0; i < 4; i++ {
		aba.estValues[i] = make(map[int][]int, aba.n)
		aba.auxValues[i] = make(map[int][]int, aba.n)
		aba.confValues[i] = make(map[int][]int, aba.n)
		aba.estSent[i] = make(map[int]bool, 2)
		aba.auxSent[i] = make(map[int]bool, 2)
		aba.confSent[i] = make(map[int]bool, 2)
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
		case <-aba.abaCh:
			aba.wg.Add(1)
		case <-aba.abaSignal:
		case e := <-aba.estCh:
			aba.est = e
			aba.wg.Add(1)
			go aba.genesis()
		}
	}

	aba.wg.Wait()
	aba.done <- true
}

func (aba *ABA) genesis() {
	defer aba.wg.Done()

	aba.mu.Lock()
	if _, ok := aba.estSent[aba.subround][aba.est]; ok {
		aba.logger.Printf("[Round:%d] [SubRound:%d] Peer has been broadcast est [%d] value.\n",
			aba.round, aba.subround, aba.est)
		aba.mu.Unlock()
		return
	}
	aba.mu.Unlock()

	aba.sendESTtoNetChannel()
}

func (aba *ABA) sendESTtoNetChannel() {
	abaEst := message.GenABAMsg(aba.round, aba.subround, aba.id)
	abaEst.ConsensusMsgField.ABAMsgField.ESTField = &message.EST{
		BinValue: aba.est,
	}
	aba.networkCh <- NetworkMsg{broadcast: true, msg: abaEst}
}

// Start ABA
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
