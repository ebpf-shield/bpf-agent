package apperrors

import "errors"

var ErrInvalidEnv = errors.New("invalid environment")

var ErrUUIDExists = errors.New("uuid already exists")
