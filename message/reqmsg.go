package message

type ReqMsg struct {
	// Request message wrapper
	NetworkMangeField *NetworkMange
	ConfigField       *Config
	ConsensusMsgField *ConsensusMsg
}

type ResMsg struct {
	// Response message
	ResponseField ClientRes
}
