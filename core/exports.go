package core

import (
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/core/model"
)

type (
	User         = model.User
	Session      = model.Session
	Account      = model.Account
	Verification = model.Verification
	RateLimit    = model.RateLimit
	Request      = contract.Request
	Response     = contract.Response
	APIError     = contract.APIError
	Endpoint     = engine.Endpoint
	Plugin       = engine.Plugin
	DirectInput  = engine.DirectInput
)
