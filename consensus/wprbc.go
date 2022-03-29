package consensus

import (
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type WPRBC struct {
	// WaitGroup to wait for all goroutine done
	// Wprbc channel to read data from acs
	// Stop channel exit wprbc
	// RBC channnel to notify acs rbc done
	// Wp channel to notify wprbc done
	// Done channel to notify acs
	wg      sync.WaitGroup
	wprbcCh chan *message.WprbcReq
	stopCh  chan bool
	rbcCh   chan []byte
	wpCh    chan []byte
	done    chan bool
}

func MakeWprbc() *WPRBC {
	wp := &WPRBC{}
	wp.wprbcCh = make(chan *message.WprbcReq)
	wp.stopCh = make(chan bool)
	wp.rbcCh = make(chan []byte)
	wp.wpCh = make(chan []byte)
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
			go wp.outputWp(msg)
		}
	}

	wp.wg.Wait()
	wp.done <- true
}

func (wp *WPRBC) outputWp(msg *message.WprbcReq) {
	defer func() {
		wp.wg.Done()
	}()

	if msg.Req%5 == 0 {
		select {
		case <-wp.stopCh:
			return
		case wp.wpCh <- []byte("Hello"):
		}
	}
}

// Send data to wprbc channel
func (wp *WPRBC) InputValue(msg *message.WprbcReq) {
	wp.wprbcCh <- msg
}

// Output wprbc channel
func (wp *WPRBC) Output() <-chan []byte {
	return wp.wpCh
}

// Close wprbc channel
func (wp *WPRBC) Stop() {
	close(wp.stopCh)
}

// Done channel
func (wp *WPRBC) Done() <-chan bool {
	return wp.done
}
