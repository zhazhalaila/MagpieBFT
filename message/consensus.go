package message

type ConsensusConfig struct {
	BatchSize int
}

type InputTx struct {
	Transactions [][]byte
	ClientId     int
	ReqCount     int
}

type ConsensusMsg struct {
	// Consensus msg wrapper
	Round                int
	ConsensusConfigField *ConsensusConfig
	InputTxField         *InputTx
	PCBCReqField         *PCBCReq
	PBMsgField           *PBMsg
	ElectMsgField        *ElectMsg
	ABAMsgField          *ABAMsg
	DecideMsgField       *DecideMsg
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
