package models

import "time"

type Agent struct {
	Name               string    `json:"name" validate:"required,min=1,max=100"`
	CreatedAt          time.Time `json:"createdAt" validate:"omitzero"`
	UpdatedAt          time.Time `json:"updatedAt" validate:"omitzero"`
	Online             bool      `json:"online" validate:"boolean"`
	ProcessesToExclude []string  `json:"processesToExclude" validate:"omitempty,min=1,max=100"`
}
