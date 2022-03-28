package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type ConsensusModule struct {
	wg           sync.WaitGroup
	acsInstances map[int]*ACS
	// Consume channel to read data from network.
	// Stop channel to stop read data from network.
	// Release channel to notify network exit.
	// Exit channel to notify sub module for loop goroutine exit.
	consumeCh chan message.ReqMsg
	stopCh    chan bool
	releaseCh chan bool
	exitCh    chan bool
}

func MakeConsensusModule(releaseCh chan bool) *ConsensusModule {
	cm := &ConsensusModule{}
	cm.acsInstances = make(map[int]*ACS)
	cm.releaseCh = releaseCh
	cm.exitCh = make(chan bool)
	return cm
}

func (cm *ConsensusModule) Consume(consumeCh chan message.ReqMsg, stopCh chan bool) {
	cm.consumeCh = consumeCh
	cm.stopCh = stopCh

L:
	for {
		select {
		case <-cm.stopCh:
			break L
		case msg := <-cm.consumeCh:
			if _, ok := cm.acsInstances[msg.Round]; !ok {
				cm.acsInstances[msg.Round] = MakeAcs(&cm.wg, cm.exitCh)
			}
			cm.acsInstances[msg.Round].InputValue(msg)
		}
	}

	fmt.Println("Network close")

	// Stop all acs instances.
	for _, acs := range cm.acsInstances {
		acs.Stop()
	}

	fmt.Println("Stop all acs instance.")

	// Wait for all created goroutines done.
	cm.wg.Wait()

	fmt.Println("All created goroutine done")

	// Close exit channel to notify for loop goroutine done. e.g. acs.monitor
	close(cm.exitCh)

	time.Sleep(10 * time.Millisecond)

	// Release network.
	cm.releaseCh <- true
}
