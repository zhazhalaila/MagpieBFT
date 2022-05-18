package message

type DecideMsg struct {
	// Parties will broadcasr proofs after deliver n-f wprbc instances
	// Send proof bytes not map to avoid concurrent map fatal error
	Proofs   []byte
	Proposer int
	Leader   int
	NotRecv  bool
}

func GenDecideMsg(round int) ReqMsg {
	msg := GenConsensusMsg(round)
	return msg
}
