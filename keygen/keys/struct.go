package keys

type PriShare struct {
	Index int    `json:"Index"`
	Pri   []byte `json:"Pri"`
}

type PubShare struct {
	Index int    `json:"Index"`
	Pub   []byte `json:"Pub"`
}
