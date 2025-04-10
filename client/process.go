package client

import (
	"fmt"

	"github.com/ebpf-shield/bpf-agent/configs"
	"github.com/ebpf-shield/bpf-agent/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"resty.dev/v3"
)

type processService interface {
	ReplaceProcesses(processes []models.Process, agentId bson.ObjectID) error
	FindByAgentIdWithRulesByCommand(agentId bson.ObjectID) ([]models.GetRulesByCommandDTO, error)
}

const processPrefix = "/process"

type processServiceImpl struct {
	restyClient *resty.Client
}

func newProcessService(restyClient *resty.Client) processService {
	return &processServiceImpl{
		restyClient: restyClient,
	}
}

func (p *processServiceImpl) ReplaceProcesses(processes []models.Process, agentId bson.ObjectID) error {
	routeUrl := fmt.Sprintf("%s/agent/%s", processPrefix, agentId.Hex())
	res, err := p.restyClient.R().SetBody(processes).Patch(routeUrl)
	if err != nil {
		return err
	}

	if res.IsError() {
		return res.Err
	}

	return nil
}

func (p *processServiceImpl) FindByAgentIdWithRulesByCommand(agentId bson.ObjectID) ([]models.GetRulesByCommandDTO, error) {
	routeUrl := fmt.Sprintf("%s/agent/%s/command/rules", processPrefix, agentId.Hex())

	result := new([]models.GetRulesByCommandDTO)
	res, err := p.restyClient.R().SetResult(result).Get(routeUrl)
	if err != nil {
		return nil, err
	}

	if err := configs.GetValidator().Struct(result); err != nil {
		return nil, err
	}

	if res.IsError() {
		return nil, res.Err
	}

	return *result, nil
}
