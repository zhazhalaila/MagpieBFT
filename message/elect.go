package message

type Elect struct {
	ElectHash []byte
	Share     []byte
}

type ElectMsg struct {
	// It is possible to have multiple elections to elect the leader
	// (most nodes deliver PB instances of the leader)
	Epoch       int
	Sender      int
	ElectFileld Elect
}

// Elect message generator
func GenElectMsg(round, epoch, sender int) ReqMsg {
	msg := GenConsensusMsg(round)
	msg.ConsensusMsgField.ElectMsgField = &ElectMsg{
		Epoch:  epoch,
		Sender: sender,
	}
	return msg
}
