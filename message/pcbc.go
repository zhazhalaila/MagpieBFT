package message

type VAL struct {
	// Merkle root hash, branch to verify shard belong to merkle tree
	RootHash [32]byte
	Branch   [][32]byte
	Shard    []byte
}

type ECHO struct {
	RootHash [32]byte
	Branch   [][32]byte
	Shard    []byte
}

type READY struct {
	RootHash [32]byte
}

type PartialShare struct {
	RootHash [32]byte
	Share    []byte
}

type PROOF struct {
	Signature []byte
	RootHash  [32]byte
}

type PCBCReq struct {
	// Only proposer can send VAL msg to start PCBC phase
	Proposer          int
	Sender            int
	Req               int
	VALField          *VAL
	ECHOField         *ECHO
	READYField        *READY
	PartialShareField *PartialShare
	PROOFField        *PROOF
}

// PCBC message generator
func GenPCBCMsg(sender, round, proposer int) ReqMsg {
	msg := GenConsensusMsg(round)
	msg.ConsensusMsgField.PCBCReqField = &PCBCReq{
		Proposer: proposer,
		Sender:   sender,
	}
	return msg
}
