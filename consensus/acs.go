package consensus

import (
	"fmt"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type ACSOut struct {
	// Write msg to network
	// Broadcast msg or send msg to peer
	broadcast bool
	peerId    int
	msg       message.ReqMsg
}

type ACSEvent struct {
	// Global channel to receive child module
	// Once child module done. e.g. rbc output | ba output ... notify acs
	// Common leader was elected from elect phase
	status       int
	leader       int
	rbcOut       []byte
	wprbcOut     []byte
	commonLeader int
	baOut        int
}

type ACS struct {
	// WaitGroup to wait for all created goroutine(write msg to network) done
	wg sync.WaitGroup
	// Current round
	round int
	// ACS in channel to read data from consensus module
	// ACS out channel write data to network
	// Stop channel to exit acs
	// Done channel to notify consensus
	// Child Event channel to receive msg from child module
	// ACS output txs to consensus
	acsIn    chan *message.ConsensusMsg
	acsOut   chan ACSOut
	stopCh   chan bool
	doneCh   chan bool
	acsEvent chan ACSEvent
	// Output channel to consensus
	outputCh chan [][]byte
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	wpInstances []*WPRBC
}

func MakeAcs(outputCh chan [][]byte) *ACS {
	acs := &ACS{}
	acs.acsIn = make(chan *message.ConsensusMsg, 100)
	acs.acsOut = make(chan ACSOut, 100)
	acs.stopCh = make(chan bool)
	acs.doneCh = make(chan bool)
	acs.acsEvent = make(chan ACSEvent, 100)
	acs.outputCh = outputCh
	acs.wpInstances = make([]*WPRBC, 10)

	// Init wprbc instances
	for i := 0; i < len(acs.wpInstances); i++ {
		acs.wpInstances[i] = MakeWprbc(acs.acsEvent, acs.acsOut)
	}

	go acs.run()
	return acs
}

func (acs *ACS) run() {
L:
	for {
		select {
		case <-acs.stopCh:
			for i := 0; i < len(acs.wpInstances); i++ {
				acs.wpInstances[i].Stop()
			}
			break L
		case msg := <-acs.acsIn:
			acs.handlemsg(msg)
		case <-acs.acsEvent:
			// fmt.Println(msg)
		case reqMsg := <-acs.acsOut:
			fmt.Println(reqMsg)
		}
	}

	// Wait for all wprbc instances done
	for i := 0; i < len(acs.wpInstances); i++ {
		<-acs.wpInstances[i].Done()
	}

	acs.doneCh <- true
}

func (acs *ACS) handlemsg(msg *message.ConsensusMsg) {
	if msg.WprbcReqField != nil {
		acs.wpInstances[msg.WprbcReqField.Proposer].InputValue(msg.WprbcReqField)
	}
}

// Output data to consensus
func (acs *ACS) output(results [][]byte) {
	select {
	case <-acs.stopCh:
	case acs.outputCh <- results:
	}
}

// Send data to acs channel
func (acs *ACS) InputValue(msg *message.ConsensusMsg) {
	acs.acsIn <- msg
}

// Close acs channel
func (acs *ACS) Stop() {
	close(acs.stopCh)
}

// Done channel
func (acs *ACS) Done() <-chan bool {
	return acs.doneCh
}
