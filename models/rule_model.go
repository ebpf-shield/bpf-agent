package models

type Rule struct {
	Saddr    string `json:"saddr" validate:"cidr"`
	Sport    uint16 `json:"sport" validate:"gt=0,lt=65536"`
	Dport    uint16 `json:"dport" validate:"gt=0,lt=65536"`
	Daddr    string `json:"daddr" validate:"cidr"`
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
