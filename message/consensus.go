package message

type ConsensusMsg struct {
	// Consensus msg wrapper
	Sender        int
	Round         int
	WprbcReqField *WprbcReq
}
