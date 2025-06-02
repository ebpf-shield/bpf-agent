package models

type Process struct {
	Command string `json:"command" validate:"required,le=400"`
	PID     int    `json:"pid" validate:"ge=0,lt=1000000,required"`
}
