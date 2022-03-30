package message

type ClientRes struct {
	// Consensus round
	Round int
	// Who has compleyed consensus for client request
	PeerId   int
	ReqCount int
	Results  []byte
}
