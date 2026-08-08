package oidcprovider

import (
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) userInfo(ctx *engine.Context) (contract.Response, error) {
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	if authorization == "" {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_request", "authorization header not found",
		)
	}
	tokenValue := strings.TrimPrefix(authorization, "Bearer ")
	record, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "accessToken", Value: tokenValue}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if record == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_token", "invalid access token",
		)
	}
	token, err := accessTokenFromRecord(record)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if token.AccessTokenExpiresAt.Before(p.clock()) {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_token", "The Access Token expired",
		)
	}
	client, err := p.findClient(ctx, token.ClientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_token", "client not found",
		)
	}
	user, err := p.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: token.UserID}},
	})
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if user == nil {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_token", "user not found",
		)
	}
	scopes := strings.Fields(token.Scopes)
	userID, _ := recordString(user, "id")
	name, _ := recordString(user, "name")
	email, _ := recordString(user, "email")
	image, imageExists := recordString(user, "image")
	emailVerified, _ := recordBool(user, "emailVerified")
	parts := strings.Split(name, " ")
	firstName := ""
	lastName := ""
	if len(parts) > 0 {
		firstName = parts[0]
	}
	if len(parts) > 1 {
		lastName = parts[1]
	}
	claims := map[string]any{"sub": userID}
	if contains(scopes, "email") {
		claims["email"] = email
		claims["email_verified"] = emailVerified
	}
	if contains(scopes, "profile") {
		claims["name"] = name
		if imageExists {
			claims["picture"] = image
		} else {
			claims["picture"] = nil
		}
		claims["given_name"] = firstName
		claims["family_name"] = lastName
	}
	if p.options.GetAdditionalUserInfoClaim != nil {
		additional, err := p.options.GetAdditionalUserInfoClaim(
			ctx.GoContext(), user, append([]string(nil), scopes...), cloneClient(*client),
		)
		if err != nil {
			return contract.Response{}, internalError(err)
		}
		for key, value := range additional {
			claims[key] = value
		}
	}
	return jsonResponse(contract.StatusOK, claims)
}
