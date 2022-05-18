package consensus

import (
	"encoding/json"
	"log"
	"sort"
	"sync"

	"github.com/sasha-s/go-deadlock"
	"github.com/zhazhalaila/BFTProtocol/message"
	"github.com/zhazhalaila/BFTProtocol/verify"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type DecideMsgWithSeenProofs struct {
	seenProofs map[int]message.PROOF
	decideMsg  *message.DecideMsg
}

type Decide struct {
	// Global log
	logger *log.Logger
	// Mutex to prevent data race
	mu deadlock.Mutex
	// N(total peers number) F(byzantine peers number) Id(peer identify)
	// Round (Create PB instance round)
	// Epoch (One election maybe not enough)
	n     int
	f     int
	id    int
	round int
	// Cache all proofs within decide msg
	proofsCache map[int]map[int]message.PROOF
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	// WaitGroup to wait for all goroutine done
	// Decide channel to read data from acs
	// Stop channel exit decide
	// Event channel to notify acs
	// Done channel to notify acs
	wg       sync.WaitGroup
	decideCh chan DecideMsgWithSeenProofs
	stopCh   chan bool
	acsEvent chan ACSEvent
	done     chan bool
}

func MakeDecide(logger *log.Logger,
	n, f, id, round int,
	suite *bn256.Suite, pubKey *share.PubPoly,
	acsEvent chan ACSEvent,
) *Decide {
	d := &Decide{}
	d.logger = logger
	d.n = n
	d.f = f
	d.id = id
	d.round = round
	d.proofsCache = make(map[int]map[int]message.PROOF)
	d.suite = suite
	d.pubKey = pubKey
	d.decideCh = make(chan DecideMsgWithSeenProofs, d.n)
	d.stopCh = make(chan bool)
	d.acsEvent = acsEvent
	d.done = make(chan bool)
	go d.run()
	return d
}

func (d *Decide) run() {
L:
	for {
		select {
		case <-d.stopCh:
			break L
		case msg := <-d.decideCh:
			d.wg.Add(1)
			go d.decideHandler(msg.seenProofs, msg.decideMsg)
		}
	}

	d.wg.Wait()
	d.done <- true
}

func (d *Decide) decideHandler(seenProofs map[int]message.PROOF, dec *message.DecideMsg) {
	defer d.wg.Done()

	d.mu.Lock()
	if _, ok := d.proofsCache[dec.Proposer]; ok {
		d.mu.Unlock()
		return
	}

	if dec.NotRecv {
		d.proofsCache[dec.Proposer] = nil
	} else {
		var proofs map[int]message.PROOF
		err := json.Unmarshal(dec.Proofs, &proofs)
		if err != nil {
			d.logger.Printf("[Round:%d] unmarshal decide err:%s from [Proposer:%d].\n", d.round, err, dec.Proposer)
			d.proofsCache[dec.Proposer] = nil
		} else {
			d.proofsCache[dec.Proposer] = proofs
		}
	}

	if len(d.proofsCache) != 2*d.f+1 {
		d.mu.Unlock()
		return
	}

	for _, proofs := range d.proofsCache {
		if proofs == nil {
			continue
		}

		valid := true
		for id, proof := range proofs {
			if _, ok := seenProofs[id]; ok {
				continue
			}
			err := verify.SignatureVerify(proof.RootHash[:], proof.Signature, d.suite, d.pubKey)
			if err != nil {
				d.logger.Printf("[Round:%d] receive invalid decide msg from [Proposer:%d].\n", d.round, id)
				valid = false
			}
		}
		if valid {
			rbcInstances := make([]int, 0)
			for id := range proofs {
				rbcInstances = append(rbcInstances, id)
			}
			d.mu.Unlock()
			select {
			case <-d.stopCh:
				return
			default:
				// Ordered.
				sort.Ints(rbcInstances)
				d.acsEvent <- ACSEvent{status: message.DECIDE, decide: rbcInstances}
			}
			// Break the outer loop.
			return
		}
	}
}

// Send data to decide channel
func (d *Decide) InputValue(seenProofs map[int]message.PROOF, msg *message.DecideMsg) {
	decideWrapper := DecideMsgWithSeenProofs{}
	decideWrapper.seenProofs = seenProofs
	decideWrapper.decideMsg = msg
	d.decideCh <- decideWrapper
}

// Close decide channel
func (d *Decide) Stop() {
	close(d.stopCh)
}

// Done channel
func (d *Decide) Done() <-chan bool {
	return d.done
}
