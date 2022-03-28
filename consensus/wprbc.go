package consensus

import (
	"fmt"
	"sync"

	"github.com/zhazhalaila/BFTProtocol/message"
)

type WPRBC struct {
	// wg to wait for all goroutine done
	// wprbc channel to read data from acs
	// stop channel exit wprbc
	// rbc channnel to notify acs rbc done
	// wp channel to notify wprbc done
	wg      *sync.WaitGroup
	wprbcCh chan *message.WprbcReq
	stopCh  chan bool
	rbcCh   chan []byte
	wpCh    chan []byte
}

func MakeWprbc(wg *sync.WaitGroup) *WPRBC {
	wp := &WPRBC{}
	wp.wg = wg
	wp.wprbcCh = make(chan *message.WprbcReq)
	wp.stopCh = make(chan bool)
	wp.rbcCh = make(chan []byte)
	wp.wpCh = make(chan []byte)
	go wp.run()
	return wp
}

func (wp *WPRBC) run() {
	for {
		select {
		case <-wp.stopCh:
			return
		case msg := <-wp.wprbcCh:
			wp.wg.Add(1)
			go wp.outputWp(msg)
		}
	}
}

func (wp *WPRBC) outputWp(msg *message.WprbcReq) {
	defer func() {
		if msg.Req%5 == 0 {
			fmt.Printf("[%d] Goroutine has sent result to acs.\n", msg.Req)
		}
		wp.wg.Done()
	}()

	if msg.Req%5 == 0 {
		select {
		case <-wp.stopCh:
			return
		case wp.wpCh <- []byte("Hello"):
			fmt.Printf("[%d] Goroutine start send result to acs.\n", msg.Req)
		}
	}
}

// Output wprbc channel
func (wp *WPRBC) Output() <-chan []byte {
	return wp.wpCh
}

// Close wprbc channel
func (wp *WPRBC) Stop() {
	close(wp.stopCh)
}

// Send data to wprbc channel
func (wp *WPRBC) InputValue(msg *message.WprbcReq) {
	wp.wprbcCh <- msg
}
