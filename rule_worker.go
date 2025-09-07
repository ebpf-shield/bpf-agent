package main

import (
	"context"
	"log"
	"time"

	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	ebpfloader "github.com/ebpf-shield/bpf-agent/ebpf_loader"
	"github.com/ebpf-shield/bpf-agent/utils"
)

func ruleSyncWorker(ctx context.Context) {
	httpClient := client.GetClient()
	firewallObjs := ebpfloader.GetFirewallObjects()
	tick := time.Tick(time.Second * 5)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			id := configs.GetRegisteredAgent().ID
			data, err := httpClient.Process().FindByAgentIdWithRulesByCommand(id)
			if err != nil {
				log.Println("Failed to get rules by command:", err)
				// TODO: return the error with errgroup
				continue
			}

			key := ebpfloader.NewFirewallCmdKeySFromComm("")
			val := ebpfloader.NewEmptyFirewallRuleArrayS()

			iter := ebpfloader.GetFirewallObjects().FirewallRules.Iterate()
			for iter.Next(key, val) {
				comm := utils.IntArrayToString(key.Comm[:])
				if rules, ok := data[comm]; ok {
					newVal := ebpfloader.NewEmptyFirewallRuleArrayS()
					newVal.RuleCount = int32(len(rules))

					if newVal.RuleCount == 0 {
						firewallObjs.FirewallRules.Put(key, newVal)
						delete(data, comm)
						continue
					}

					for i, rule := range rules {
						ebpfloader.SetRuleToFirewallRuleArrayEntry(rule, newVal, int32(i))
					}

					firewallObjs.FirewallRules.Put(key, newVal)
					delete(data, comm)
				} else {
					ebpfloader.GetFirewallObjects().FirewallRules.Delete(key)
				}
			}

			for comm, rules := range data {
				key := ebpfloader.NewFirewallCmdKeySFromComm(comm)
				newVal := ebpfloader.NewEmptyFirewallRuleArrayS()
				newVal.RuleCount = int32(len(rules))

				// We can do a lookup and then return error if exists
				// err := firewallObjs.FirewallRules.Lookup(key, val)

				if newVal.RuleCount == 0 {
					firewallObjs.FirewallRules.Put(key, newVal)
					continue
				}

				for i, rule := range rules {
					ebpfloader.SetRuleToFirewallRuleArrayEntry(rule, newVal, int32(i))
				}

				firewallObjs.FirewallRules.Put(key, newVal)
			}
		}
	}
}
