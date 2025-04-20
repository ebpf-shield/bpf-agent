package ebpfloader

import (
	"log"
	"sync"
)

var (
	objs         firewallObjects
	initObjsOnce sync.Once
)

func LoadFirewallObjects() (*firewallObjects, error) {
	var err error
	initObjsOnce.Do(func() {
		if err = loadFirewallObjects(&objs, nil); err != nil {
			log.Fatalf("loading objects: %v", err)
		}
	})

	if err != nil {
		return nil, err
	}

	return &objs, nil
}

func GetFirewallObjects() *firewallObjects {
	return &objs
}

func NewFirewallCmdKeySFromComm(comm string) *firewallCmdKeyS {
	bytesComm := new(firewallCmdKeyS)
	for i := 0; i < len(comm) && i < len(bytesComm.Comm); i++ {
		bytesComm.Comm[i] = int8(comm[i])
	}

	return bytesComm
}

func NewEmptyFirewallRuleArrayS() *firewallRuleArrayS {
	res := new(firewallRuleArrayS)

	return res
}
