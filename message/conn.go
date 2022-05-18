package message

type ConnectPeer struct {
	// Peer address and identify
	PeerAddr string
	PeerId   int
}

type DisConnectPeer struct {
	// Peer identify
	PeerId int
}

type SetClient struct {
	// Client identify
	ClientId int
}

type DisconnectClient struct {
	// Client identify
	ClientId int
}

type NetworkMange struct {
	// Struct wrapper
	ConnPeerField         *ConnectPeer
	DisConnPeerField      *DisConnectPeer
	SetClientField        *SetClient
	DisconnectClientField *DisconnectClient
}

// Generate network manage message
func GenNetMangeMsg() ReqMsg {
	netMangeMsg := ReqMsg{
		NetworkMangeField: &NetworkMange{},
	}
	return netMangeMsg
}
