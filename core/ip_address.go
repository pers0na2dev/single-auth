package core

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
)

func (a *Auth) resolveIPAddress(request contract.Request) string {
	if a == nil {
		return ""
	}
	options := cloneIPOptions(a.options.Advanced.IPAddress)
	environment := strings.ToLower(strings.TrimSpace(a.options.Environment))
	options.Development = options.Development || environment == "development"
	options.Test = options.Test || environment == "test"
	return ratelimit.GetIP(ratelimit.HeaderGetterFunc(func(name string) string {
		return strings.Join(request.Headers().Values(name), ", ")
	}), options)
}
