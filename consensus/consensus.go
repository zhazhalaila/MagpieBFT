package consensus

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/zhazhalaila/BFTProtocol/keygen/decodekeys"
	"github.com/zhazhalaila/BFTProtocol/libnet"
	"github.com/zhazhalaila/BFTProtocol/message"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

const (
	// Transanction status
	WAIT    = iota
	PROCESS = iota
	SUCCESS = iota
)

type txWithStatus struct {
	status int
	tx     []byte
}

type ConsensusModule struct {
	// Global log
	logger *log.Logger
	// Network module
	network *libnet.Network
	// WaitGroup wait for start acs goroutine done
	wg sync.WaitGroup
	// N = Total peers number, F = Byzantine peers number, ID = current peer identify
	n  int
	f  int
	id int
	// Used to crypto
	suite  *bn256.Suite
	pubKey *share.PubPoly
	priKey *share.PriShare
	// Current round
	round int
	// Transactions size to consensus within one round
	// Implement buffer to buffer transactions
	// If acs done, close acs
	batchSize    int
	buffer       []txWithStatus
	acsInstances map[int]*ACS
	acsDone      map[int]bool
	// Output channel to receive data from acs
	// Clear channel to clear acs instance
	acsOutCh chan int
	acsClear chan int
	// Consume channel to read data from network
	// Stop channel to stop read data from network
	// Release channel to notify network exit
	consumeCh chan *message.ConsensusMsg
	stopCh    chan bool
	releaseCh chan bool
}

func MakeConsensusModule(logger *log.Logger,
	network *libnet.Network,
	releaseCh chan bool,
	n, f, id int) *ConsensusModule {
	cm := &ConsensusModule{}
	cm.logger = logger
	cm.network = network
	cm.n = n
	cm.f = f
	cm.id = id
	cm.suite = bn256.NewSuite()
	cm.pubKey = decodekeys.DecodePubShare(cm.suite, cm.n, cm.f+1)
	cm.priKey = decodekeys.DecodePriShare(cm.suite, cm.n, cm.f+1, cm.id)
	cm.round = 0
	cm.buffer = make([]txWithStatus, 65536)
	cm.acsOutCh = make(chan int, 1000)
	cm.acsClear = make(chan int, 1000)
	cm.acsInstances = make(map[int]*ACS, 1000)
	cm.acsDone = make(map[int]bool)
	cm.releaseCh = releaseCh
	return cm
}

func (cm *ConsensusModule) Consume(consumeCh chan *message.ConsensusMsg, stopCh chan bool) {
	cm.consumeCh = consumeCh
	cm.stopCh = stopCh

L:
	for {
		select {
		case <-cm.stopCh:
			break L
		case msg := <-cm.consumeCh:
			cm.handleMsg(msg)
		case acsId := <-cm.acsOutCh:
			cm.logger.Printf("[Round:%d] done.\n", acsId)
			if !cm.acsDone[acsId] {
				cm.acsDone[acsId] = true
				cm.acsInstances[acsId].Stop()
			}
		case acsId := <-cm.acsClear:
			cm.acsInstances[acsId] = nil
			cm.logger.Printf("[Round:%d] clear.\n", acsId)
		case <-time.After(1 * time.Second):
			cm.logger.Println("Long time not receive msg from peers...")
		}
	}

	fmt.Println("Network close")

	// Stop all un done acs instances.
	fmt.Println("Stop all acs instance.")
	for id, acs := range cm.acsInstances {
		if !cm.acsDone[id] {
			cm.acsDone[id] = true
			acs.Stop()
		}
	}

	// Wait for all created acs done.
	for _, acs := range cm.acsInstances {
		<-acs.Done()
	}

	fmt.Println("All created goroutine done")

	// Release network.
	cm.releaseCh <- true
}

func (cm *ConsensusModule) handleMsg(msg *message.ConsensusMsg) {
	if msg.InputTxField != nil {
		cm.logger.Printf("[Round:%d] Consensus Receive Txs from client.\n", cm.round)
		for _, tx := range msg.InputTxField.Transactions {
			cm.buffer = append(cm.buffer, txWithStatus{status: PROCESS, tx: tx})
		}
		round := cm.round
		cm.startACS(msg.InputTxField.Transactions, round)
		cm.round++
	} else {
		if cm.acsDone[msg.Round] {
			return
		}
		if _, ok := cm.acsInstances[msg.Round]; !ok {
			cm.acsMaker(msg.Round)
			cm.acsDone[msg.Round] = false
		}
		cm.acsInstances[msg.Round].InputValue(msg)
	}

}

func (cm *ConsensusModule) startACS(transactions [][]byte, round int) {
	if _, ok := cm.acsInstances[round]; !ok {
		cm.acsMaker(round)
		cm.acsDone[round] = false
	}
	cm.acsInstances[round].InputTxs(transactions)
}

// Create new acs
func (cm *ConsensusModule) acsMaker(round int) {
	cm.acsInstances[round] = MakeAcs(cm.logger,
		cm.network, cm.n, cm.f, cm.id, round,
		cm.suite, cm.pubKey, cm.priKey,
		cm.acsOutCh, cm.acsClear)
}
