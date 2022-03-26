package consensus

import (
	"fmt"
	"sync"
	"time"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type ConsensusModule struct {
	wg        sync.WaitGroup
	consumeCh chan message.ReqMsg
	releaseCh chan bool
}

func MakeConsensusModule(consumeCh chan message.ReqMsg, releaseCh chan bool) *ConsensusModule {
	cm := &ConsensusModule{}
	cm.consumeCh = consumeCh
	cm.releaseCh = releaseCh
	return cm
}

func (cm *ConsensusModule) Run() {
	for msg := range cm.consumeCh {
		cm.wg.Add(1)
		go cm.handle(msg)
	}

	fmt.Println("do this???")
	// Wait for all goroutine done.
	cm.wg.Wait()

	// Release network.
	cm.releaseCh <- true
}

func (cm *ConsensusModule) handle(msg message.ReqMsg) {
	defer cm.wg.Done()
	time.Sleep(10 * time.Millisecond)
}
