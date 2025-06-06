package apperrors

import "errors"

var ErrInvalidEnv = errors.New("invalid environment")

var ErrUnknownResty = errors.New("unknown resty error")
