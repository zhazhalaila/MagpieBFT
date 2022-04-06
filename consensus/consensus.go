package consensus

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/keygen/decodekeys"
	"github.com/zhazhalaila/BFTProtocol/libnet"
	merkletree "github.com/zhazhalaila/BFTProtocol/merkleTree"
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
	batchSize    int
	buffer       []txWithStatus
	acsInstances map[int]*ACS
	// Output channel to receive data from acs
	acsOutCh chan [][]byte
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
	cm.acsOutCh = make(chan [][]byte, 100)
	cm.acsInstances = make(map[int]*ACS)
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
		case <-cm.acsOutCh:
		}
	}

	fmt.Println("Network close")

	// Stop all acs instances.
	fmt.Println("Stop all acs instance.")
	for _, acs := range cm.acsInstances {
		acs.Stop()
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
		for _, tx := range msg.InputTxField.Transactions {
			cm.buffer = append(cm.buffer, txWithStatus{status: PROCESS, tx: tx})
		}
		round := cm.round
		cm.startACS(msg.InputTxField.Transactions, round)
		cm.round++
	} else {
		if _, ok := cm.acsInstances[msg.Round]; !ok {
			cm.acsMaker(msg.Round)
		}
		cm.acsInstances[msg.Round].InputValue(msg)
	}

}

func (cm *ConsensusModule) startACS(transactions [][]byte, round int) {
	if _, ok := cm.acsInstances[round]; !ok {
		cm.acsMaker(round)
	}
	// Marshal
	txsBytes, err := json.Marshal(transactions)
	if err != nil {
		// log
		return
	}
	// Erasure code
	shards, err := ECEncode(cm.f+1, cm.n-(cm.f+1), txsBytes)
	if err != nil {
		// log
		return
	}
	// Merkle tree
	mt, err := merkletree.MakeMerkleTree(shards)
	if err != nil {
		// log
		return
	}
	rootHash := mt[1]

	// Broadcast val msg
	cm.wg.Add(1)
	go func() {
		defer cm.wg.Done()

		for i := 0; i < cm.n; i++ {
			branch := merkletree.GetMerkleBranch(i, mt)
			msg := message.GenWPRBCMsg(cm.id, round, cm.id)
			msg.ConsensusMsgField.WprbcReqField.VALField = &message.VAL{
				RootHash: rootHash,
				Branch:   branch,
				Shard:    shards[i],
			}
			cm.network.SendToPeer(i, msg)
		}
	}()
}

// Create new acs
func (cm *ConsensusModule) acsMaker(round int) {
	cm.acsInstances[round] = MakeAcs(cm.logger,
		cm.network, cm.n, cm.f, cm.id, cm.round,
		cm.suite, cm.pubKey, cm.priKey,
		cm.acsOutCh)
}
