package models

type Rule struct {
	Saddr    string `json:"saddr" validate:"required,ip"`
	Dport    uint16 `json:"dport" validate:"required,gt=0,lt=65536"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Chain    string `json:"chain"`
}

type GetRulesByCommandDTO struct {
	Command string `json:"command" validate:"required"`
	Rules   []Rule `json:"rules"`
}
