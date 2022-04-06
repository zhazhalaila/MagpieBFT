package message

type EST struct {
	// Estimate value
	BinValue int
}

type AUX struct {
	// Have seen 2f+1 times estimate value
	Element int
}

type CONF struct {
	// Have seen 2f+1 aux values
	Value int
}

type COIN struct {
	// Hash("Round+Subround")
	// Share(HashMsg)
	HashMsg []byte
	Share   []byte
}

type ABAMsg struct {
	InstanceId int
	SubRound   int
	Sender     int
	ESTField   *EST
	AUXField   *AUX
	CONFField  *CONF
	COINField  *COIN
}

func GenABAMsg(round, instanceId, subround, sender int) ReqMsg {
	msg := GenConsensusMsg(round)
	msg.ConsensusMsgField.ABAMsgField = &ABAMsg{
		InstanceId: instanceId,
		SubRound:   subround,
		Sender:     sender,
	}
	return msg
}
