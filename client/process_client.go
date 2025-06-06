package client

import (
	"fmt"

	"github.com/ebpf-shield/bpf-agent/configs"
	"github.com/ebpf-shield/bpf-agent/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"resty.dev/v3"
)

type processService interface {
	ReplaceProcesses(r ReplaceProcessesDTO) error
	FindByAgentIdWithRulesByCommand(agentId bson.ObjectID) (*models.GetRulesByCommandDTO, error)
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

type ReplaceProcessesDTO struct {
	Processes      []models.Process
	AgentId        bson.ObjectID
	OrganizationId bson.ObjectID
}

func (p *processServiceImpl) ReplaceProcesses(r ReplaceProcessesDTO) error {
	routeUrl := fmt.Sprintf("%s/agent/%s", processPrefix, r.AgentId.Hex())

	body := struct {
		Processes      []models.Process `json:"processes"`
		OrganizationId bson.ObjectID    `json:"organizationId"`
	}{
		Processes:      r.Processes,
		OrganizationId: r.OrganizationId,
	}

	res, err := p.restyClient.R().SetBody(&body).Patch(routeUrl)
	if err != nil {
		return err
	}

	if res.IsError() {
		return res.Err
	}

	return nil
}

func (p *processServiceImpl) FindByAgentIdWithRulesByCommand(agentId bson.ObjectID) (*models.GetRulesByCommandDTO, error) {
	routeUrl := fmt.Sprintf("%s/agent/%s/command/rules", processPrefix, agentId.Hex())

	result := new(models.GetRulesByCommandDTO)
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

	return result, nil
}
