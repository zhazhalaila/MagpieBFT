package consensus

import (
	"fmt"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type ConsensusModule struct {
	acsInstances map[int]*ACS
	// Consume channel to read data from network.
	// Stop channel to stop read data from network.
	// Release channel to notify network exit.
	consumeCh chan *message.ConsensusMsg
	stopCh    chan bool
	releaseCh chan bool
}

func MakeConsensusModule(releaseCh chan bool) *ConsensusModule {
	cm := &ConsensusModule{}
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
				cm.acsInstances[msg.Round] = MakeAcs()
			}
			cm.acsInstances[msg.Round].InputValue(msg)
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
