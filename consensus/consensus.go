package consensus

import (
	"fmt"

	"github.com/zhazhalaila/BFTProtocol/message"
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
	// N = Total peers number, F = Byzantine peers number, ID = current peer identify
	n  int
	f  int
	id int
	// Current round
	// Transactions size to consensus within one round
	// Implement buffer to buffer transactions
	round        int
	batchSize    int
	buffer       []txWithStatus
	acsInstances map[int]*ACS
	// Output channel to receive data from acs
	outputCh chan [][]byte
	// Consume channel to read data from network
	// Stop channel to stop read data from network
	// Release channel to notify network exit
	consumeCh chan *message.ConsensusMsg
	stopCh    chan bool
	releaseCh chan bool
}

func MakeConsensusModule(releaseCh chan bool) *ConsensusModule {
	cm := &ConsensusModule{}
	cm.buffer = make([]txWithStatus, 65536)
	cm.outputCh = make(chan [][]byte, 100)
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
			if _, ok := cm.acsInstances[msg.Round]; !ok {
				cm.acsInstances[msg.Round] = MakeAcs(cm.outputCh)
			}
			cm.acsInstances[msg.Round].InputValue(msg)
		case <-cm.outputCh:
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

func (cm *ConsensusModule) consensusMsgHandle(msg *message.ConsensusMsg) {
	if msg.InputTxField != nil {
		for _, tx := range msg.InputTxField.Transactions {
			cm.buffer = append(cm.buffer, txWithStatus{status: PROCESS, tx: tx})
		}

	}
}
