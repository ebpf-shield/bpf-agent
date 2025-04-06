package models

type Event struct {
	SrcIP    uint32
	DestPort uint16
	Proto    uint8
	Allowed  uint8
}
