package models

type Process struct {
	Command string `json:"command" validate:"required,le=400"`
	Count   int    `json:"count" validate:"ge=0,lt=1000000,required"`
}
