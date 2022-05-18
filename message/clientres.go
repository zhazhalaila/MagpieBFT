package message

type ClientRes struct {
	// Consensus round
	Round int
	// Request count
	ReqCount int
	// Who has compleyed consensus for client request
	PeerId  int
	Results []byte
}
