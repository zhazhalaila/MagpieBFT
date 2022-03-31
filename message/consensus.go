package message

type ConsensusMsg struct {
	// Consensus msg wrapper
	Sender        int
	Round         int
	WprbcReqField *WprbcReq
}

// Consensus message generator
func GenConsensusMsg(sender, round int) ReqMsg {
	msg := ReqMsg{
		ConsensusMsgField: &ConsensusMsg{
			Sender: sender,
			Round:  round,
		},
	}
	return msg
}
