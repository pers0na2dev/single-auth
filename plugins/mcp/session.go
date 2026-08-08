package mcp

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) getSession(ctx *engine.Context) (contract.Response, error) {
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	accessToken := strings.Replace(authorization, "Bearer ", "", 1)
	if accessToken == "" || accessToken == authorization {
		return jsonResponse(contract.StatusOK, nil)
	}
	record, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "accessToken", Value: accessToken}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if record == nil {
		return jsonResponse(contract.StatusOK, nil)
	}
	token, err := accessTokenFromRecord(record)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if token.AccessTokenExpiresAt.Before(p.clock()) {
		return jsonResponse(contract.StatusOK, nil)
	}
	return jsonResponse(contract.StatusOK, token)
}
