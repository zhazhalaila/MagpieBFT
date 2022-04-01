package message

type ConsensusConfig struct {
	BatchSize int
}

type InputTx struct {
	Transactions [][]byte
}

type ConsensusMsg struct {
	// Consensus msg wrapper
	Sender               int
	Round                int
	ConsensusConfigField *ConsensusConfig
	InputTxField         *InputTx
	WprbcReqField        *WprbcReq
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
