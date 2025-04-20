package models

type Rule struct {
	Saddr    string `json:"saddr" validate:"ip"`
	Sport    uint16 `json:"sport" validate:"gt=0,lt=65536"`
	Dport    uint16 `json:"dport" validate:"gt=0,lt=65536"`
	Daddr    string `json:"daddr" validate:"ip"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Chain    string `json:"chain"`
}

type RuleWithCommand struct {
	Command string `json:"command" validate:"required,min=1"`
	Rules   []Rule `json:"rules"`
}
type GetRulesByCommandDTO struct {
	RulesByCommand []RuleWithCommand `json:"rulesByCommand"`
}

/**
{
    __u8 proto;
    // The address has to be kept in network byte order
    __u32 daddr;
    __u16 dport;
    __u8 action;
};*/

type EbpfRule struct {
	Proto  uint8  `json:"proto"`
	Daddr  uint32 `json:"daddr"`
	Dport  uint16 `json:"dport"`
	Action uint8  `json:"action"`
}
