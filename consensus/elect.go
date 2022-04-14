package consensus

import (
	"crypto/sha256"
	"log"
	"sync"

	"github.com/sasha-s/go-deadlock"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type Elect struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu deadlock.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Round (Create PB instance round)
	// Epoch (One election maybe not enough)
	n         int
	f         int
	id        int
	round     int
	epoch     int
	shares    map[int][]byte
	siganture []byte
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// WaitGroup to wait for all goroutine done
	// Elect channel to read data from acs
	// Stop channel exit elect
	// Event channel to notify acs
	// Network channel send data to network (manage by acs)
	// Done channel to notify acs
	wg        sync.WaitGroup
	electCh   chan *message.ElectMsg
	stopCh    chan bool
	acsEvent  chan ACSEvent
	networkCh chan NetworkMsg
	done      chan bool
}

func MakeElect(logger *log.Logger,
	n, f, id, round, epoch int,
	suite *bn256.Suite, pubKey *share.PubPoly, priKey *share.PriShare,
	acsEvent chan ACSEvent, networkCh chan NetworkMsg,
) *Elect {
	e := &Elect{}
	e.logger = logger
	e.n = n
	e.f = f
	e.id = id
	e.round = round
	e.epoch = epoch
	e.shares = make(map[int][]byte)
	e.suite = suite
	e.pubKey = pubKey
	e.priKey = priKey
	e.electCh = make(chan *message.ElectMsg, e.n)
	e.stopCh = make(chan bool)
	e.acsEvent = acsEvent
	e.networkCh = networkCh
	e.done = make(chan bool)
	go e.run()
	return e
}

func (e *Elect) run() {
L:
	for {
		select {
		case <-e.stopCh:
			break L
		case msg := <-e.electCh:
			e.wg.Add(1)
			go e.electHandler(msg.ElectFileld, msg.Sender)
		}
	}

	e.wg.Wait()
	e.done <- true
}

func (e *Elect) electHandler(elec message.Elect, sender int) {
	defer e.wg.Done()

	e.mu.Lock()
	if _, ok := e.shares[sender]; ok {
		e.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] receive redundant elect msg from %d.\n",
			e.round, e.epoch, e.id, sender)
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	err := verify.ShareVerify(elec.ElectHash, elec.Share, e.suite, e.pubKey)
	if err != nil {
		e.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] receive redundant elect msg from %d.\n",
			e.round, e.epoch, e.id, sender)
		return
	}

	// e.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] receive elect msg from %d.\n",
	// 	e.round, e.epoch, e.id, sender)

	e.mu.Lock()
	e.shares[sender] = elec.Share
	if len(e.shares) == e.f+1 {
		var shares [][]byte
		for _, share := range e.shares {
			shares = append(shares, share)
		}
		e.mu.Unlock()
		// Compute siganture
		signature, err := verify.ComputeSignature(elec.ElectHash, e.suite, shares, e.pubKey, e.n, e.f+1)
		if err != nil {
			e.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] compute invalid signature.\n", e.round, e.epoch, e.id)
			e.logger.Println(err)
			return
		}

		err = verify.SignatureVerify(elec.ElectHash, signature, e.suite, e.pubKey)
		if err != nil {
			e.logger.Printf("[Round:%d] [Epoch:%d] [Peer:%d] verify signature fail.\n", e.round, e.epoch, e.id)
			e.logger.Println(err)
		}
		leaderHash := sha256.Sum256(signature)
		// Out to acs
		select {
		case <-e.stopCh:
			return
		default:
			e.acsEvent <- ACSEvent{status: message.ELECTOUTPUT, commonLeader: int(leaderHash[0]) % e.n}
		}
	} else {
		e.mu.Unlock()
	}
}

// Send data to wprbc channel
func (e *Elect) InputValue(msg *message.ElectMsg) {
	e.electCh <- msg
}

// Close wprbc channel
func (e *Elect) Stop() {
	close(e.stopCh)
}

// Done channel
func (e *Elect) Done() <-chan bool {
	return e.done
}
