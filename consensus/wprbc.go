package consensus

import (
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type WPRBC struct {
	// WaitGroup to wait for all goroutine done
	// Wprbc channel to read data from acs
	// Stop channel exit wprbc
	// Event channel to nptify acs
	// Done channel to notify acs
	wg       sync.WaitGroup
	wprbcCh  chan *message.WprbcReq
	stopCh   chan bool
	acsEvent chan ACSEvent
	done     chan bool
}

func MakeWprbc(acsEvent chan ACSEvent) *WPRBC {
	wp := &WPRBC{}
	wp.wprbcCh = make(chan *message.WprbcReq, 100)
	wp.stopCh = make(chan bool)
	wp.acsEvent = acsEvent
	wp.done = make(chan bool)
	go wp.run()
	return wp
}

func (wp *WPRBC) run() {
L:
	for {
		select {
		case <-wp.stopCh:
			break L
		case msg := <-wp.wprbcCh:
			wp.wg.Add(1)
			go wp.outputRBC(msg)
		}
	}

	wp.wg.Wait()
	wp.done <- true
}

func (wp *WPRBC) outputRBC(msg *message.WprbcReq) {
	defer func() {
		wp.wg.Done()
	}()

	if msg.Req%5 == 0 {
		select {
		case <-wp.stopCh:
			return
		case wp.acsEvent <- ACSEvent{status: message.RBCOUTPUT, leader: 2, rbcOut: []byte("hello")}:
		}
	}
}

// Send data to wprbc channel
func (wp *WPRBC) InputValue(msg *message.WprbcReq) {
	wp.wprbcCh <- msg
}

// Close wprbc channel
func (wp *WPRBC) Stop() {
	close(wp.stopCh)
}

// Done channel
func (wp *WPRBC) Done() <-chan bool {
	return wp.done
}
