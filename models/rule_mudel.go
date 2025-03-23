package models

type Rule struct {
	Saddr     string `validate:"ip"`
	Daddr     string `validate:"ip"`
	Sport     int    `validate:"gte=0,lte=65535"`
	Dport     int    `validate:"gte=0,lte=65535"`
	Protocol  string `validate:"lte=20"`
	Action    string `validate:"oneof=ACCEPT DROP"`
	Chain     string `validate:"oneof=INPUT OUTPUT"`
	ProcessId int    `validate:"gte=0"`
}
