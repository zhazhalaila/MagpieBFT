package message

type ReqMsg struct {
	Sender        int
	Round         int
	WprbcReqField *WprbcReq
}
