package message

type ConsensusConfig struct {
	BatchSize int
}

type InputTx struct {
	Transactions [][]byte
}

type ConsensusMsg struct {
	// Consensus msg wrapper
	Round                int
	ConsensusConfigField *ConsensusConfig
	InputTxField         *InputTx
	WprbcReqField        *WprbcReq
}

// Consensus message generator
func GenConsensusMsg(round int) ReqMsg {
	msg := ReqMsg{
		ConsensusMsgField: &ConsensusMsg{
			Round: round,
		},
	}
	return msg
}
