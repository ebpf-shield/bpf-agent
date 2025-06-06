package client

import (
	"fmt"

	"github.com/ebpf-shield/bpf-agent/configs"
	"go.mongodb.org/mongo-driver/v2/bson"
	"resty.dev/v3"
)

type agentService interface {
	Create(createAgentDto CreateAgentDTO) error
	ExistsById(agentId bson.ObjectID) (bool, error)
	GetProcessesToExcludeById(agentId bson.ObjectID) ([]string, error)
}

const agentPrefix = "/agent"

type agentServiceImpl struct {
	restyClient *resty.Client
}

func newAgentService(restyClient *resty.Client) agentService {
	return &agentServiceImpl{
		restyClient: restyClient,
	}
}

type CreateAgentDTO struct {
	Id             bson.ObjectID
	OrganizationId bson.ObjectID
}

func (a *agentServiceImpl) Create(createAgentDto CreateAgentDTO) error {
	routeUrl := fmt.Sprint(agentPrefix)

	body := struct {
		Id             bson.ObjectID `json:"_id"`
		OrganizationId bson.ObjectID `json:"organizationId"`
	}{
		Id:             createAgentDto.Id,
		OrganizationId: createAgentDto.OrganizationId,
	}

	res, err := a.restyClient.R().SetBody(body).Post(routeUrl)
	if err != nil {
		return err
	}

	if res.IsError() {
		return res.Err
	}

	return nil
}

func (a *agentServiceImpl) ExistsById(agentId bson.ObjectID) (bool, error) {
	routeUrl := fmt.Sprintf("%s/exists/%s", agentPrefix, agentId.Hex())
	validator := configs.GetValidator()

	resStruct := &struct {
		Exists bool `json:"exists" validate:"boolean"`
	}{
		Exists: false,
	}

	res, err := a.restyClient.R().SetResult(resStruct).Get(routeUrl)
	if err != nil {
		return false, err
	}

	if err := validator.Struct(resStruct); err != nil {
		return false, err
	}

	if res.IsError() {
		return false, res.Err
	}

	if resStruct.Exists {
		return true, nil
	}

	return false, nil
}

func (a *agentServiceImpl) GetProcessesToExcludeById(agentId bson.ObjectID) ([]string, error) {
	routeUrl := fmt.Sprintf("%s/%s/processes-to-exclude", agentPrefix, agentId.Hex())
	validator := configs.GetValidator()

	resStruct := &struct {
		ProcessesToExclude []string `json:"processesToExclude" validate:"omitempty,min=1,max=100"`
	}{}

	res, err := a.restyClient.R().SetResult(resStruct).Get(routeUrl)
	if err != nil {
		return nil, err
	}

	if err := validator.Struct(resStruct); err != nil {
		return nil, err
	}

	if res.IsError() {
		return nil, res.Err
	}

	if len(resStruct.ProcessesToExclude) == 0 {
		return nil, nil
	}

	return resStruct.ProcessesToExclude, nil
}
