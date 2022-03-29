package consensus

import (
	"github.com/zhazhalaila/BFTProtocol/message"
)

type ACS struct {
	// Acs channel to read data from consensus module.
	// Stop channel to exit acs.
	// Done channel to notify consensus.
	acsCh  chan message.ReqMsg
	stopCh chan bool
	doneCh chan bool
	// Child module. e.g. wprbc protocol, pb protocol, elect protocol and aba protocol...
	wp *WPRBC
}

func MakeAcs() *ACS {
	acs := &ACS{}
	acs.acsCh = make(chan message.ReqMsg)
	acs.stopCh = make(chan bool)
	acs.doneCh = make(chan bool)
	acs.wp = MakeWprbc()
	go acs.run()
	return acs
}

func (acs *ACS) run() {
L:
	for {
		select {
		case <-acs.stopCh:
			acs.wp.Stop()
			break L
		case msg := <-acs.acsCh:
			acs.handlemsg(msg)
		case <-acs.wp.Output():
		}
	}

	<-acs.wp.Done()
	acs.doneCh <- true
}

func (acs *ACS) handlemsg(msg message.ReqMsg) {
	if msg.WprbcReqField != nil {
		acs.wp.InputValue(msg.WprbcReqField)
	}
}

// Send data to acs channel
func (acs *ACS) InputValue(msg message.ReqMsg) {
	acs.acsCh <- msg
}

// Close acs channel
func (acs *ACS) Stop() {
	close(acs.stopCh)
}

// Done channel
func (acs *ACS) Done() <-chan bool {
	return acs.doneCh
}
