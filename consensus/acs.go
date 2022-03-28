package consensus

import (
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type ACS struct {
	// Wg synchronous wait, assign to it's child module.
	// Acs channel to read data from consensus module.
	// Stop channel to exit acs.
	// Exit channel to exit from for loop goroutine. e.g. monitor goroutine.
	wg     *sync.WaitGroup
	acsCh  chan message.ReqMsg
	stopCh chan bool
	exitCh chan bool
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	wp *WPRBC
}

func MakeAcs(wg *sync.WaitGroup, exitCh chan bool) *ACS {
	acs := &ACS{}
	acs.wg = wg
	acs.acsCh = make(chan message.ReqMsg)
	acs.stopCh = make(chan bool)
	acs.exitCh = exitCh
	acs.wp = MakeWprbc(wg)
	go acs.run()
	go acs.monitor()
	return acs
}

func (acs *ACS) run() {
	for {
		select {
		case <-acs.stopCh:
			acs.wp.Stop()
			return
		case msg := <-acs.acsCh:
			acs.handlemsg(msg)
		}
	}
}

func (acs *ACS) handlemsg(msg message.ReqMsg) {
	if msg.WprbcReqField != nil {
		acs.wp.InputValue(msg.WprbcReqField)
	}
}

func (acs *ACS) monitor() {
	for {
		select {
		case <-acs.exitCh:
			return
		case <-acs.wp.Output():
			// fmt.Println("Receive data from wprbc")
		}
	}
}

// Close acs channel
func (acs *ACS) Stop() {
	close(acs.stopCh)
}

// Send data to acs channel
func (acs *ACS) InputValue(msg message.ReqMsg) {
	acs.acsCh <- msg
}
