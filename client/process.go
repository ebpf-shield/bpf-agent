package client

import (
	"fmt"

	"github.com/ebpf-shield/bpf-agent/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"resty.dev/v3"
)

type processService interface {
	ReplaceProcesses(processes []models.Process, agentId bson.ObjectID) error
	GetRulesByCommand() ([]models.GetRulesByCommandDTO, error)
}

const processPrefix = "/process"

type processServiceImpl struct {
	restyClient *resty.Client
}

func (p *processServiceImpl) ReplaceProcesses(processes []models.Process, agentId bson.ObjectID) error {
	routeUrl := fmt.Sprintf("%s/agent/%s", processPrefix, agentId.Hex())
	res, err := p.restyClient.R().SetBody(processes).Post(routeUrl)
	if err != nil {
		return err
	}

	fmt.Println(res)

	return nil
}

func (p *processServiceImpl) GetRulesByCommand() ([]models.GetRulesByCommandDTO, error) {
	return nil, nil
}
