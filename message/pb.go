package message

type PBReq struct {
	// Parties will broadcasr proofs after deliver n-f wprbc instances
	// ProofHash gengrate by hash(Proofs)
	Proofs    map[int]PROOF
	ProofHash []byte
}

type PBRes struct {
	// Hash(Proofs) and partial share
	Endorser  int
	ProofHash []byte
	Share     []byte
}

type PBDone struct {
	// Hash(Proofs)
	ProofHash []byte
	Signature []byte
}

type PBMsg struct {
	// Proposer broadcast proofs, endorser will vote to proposer if proofs are valid
	Proposer    int
	PBReqField  *PBReq
	PBResField  *PBRes
	PBDoneField *PBDone
}

// PB message generator
func GenPBMsg(round, proposer int) ReqMsg {
	msg := GenConsensusMsg(round)
	msg.ConsensusMsgField.PBMsgField = &PBMsg{
		Proposer: proposer,
	}
	return msg
}
