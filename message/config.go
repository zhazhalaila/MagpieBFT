package message

type DelaySimulator struct {
	MinDelay int
	MaxDelay int
}

type Config struct {
	DelaySimulatorField *DelaySimulator
}
