package oidcprovider

import (
	"encoding/json"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

func (p *plugin) consent(ctx *engine.Context) (contract.Response, error) {
	if _, err := p.options.Runtime.ResolveSession(ctx, true); err != nil {
		return contract.Response{}, err
	}
	body, err := decodeBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if body == nil {
		return contract.Response{}, validationError("request body is required")
	}
	accept, ok := body["accept"].(bool)
	if !ok {
		return contract.Response{}, validationError("accept is required")
	}
	consentCode, _, err := optionalBodyString(body, "consent_code")
	if err != nil {
		return contract.Response{}, err
	}
	if consentCode == "" {
		consentCode, _ = readSignedCookie(ctx.Request(), "oidc_consent_prompt", p.options.Runtime.Secret)
	}
	if consentCode == "" {
		return contract.Response{}, oauthError(
			contract.StatusUnauthorized, "invalid_request",
			"consent_code is required (either in body or cookie)",
		)
	}
	verification, err := p.peekVerification(ctx.GoContext(), consentCode)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if verification == nil {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_request", "Invalid code")
	}
	expiresAt, validExpiry := recordTime(verification, "expiresAt")
	if !validExpiry || expiresAt.Before(p.clock()) {
		_ = p.deleteVerification(ctx.GoContext(), consentCode)
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_request", "Code expired")
	}
	expirePromptCookie(ctx, "oidc_consent_prompt")
	rawValue, ok := recordString(verification, "value")
	if !ok {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_request", "Invalid code")
	}
	var value AuthorizationCodeValue
	if err := json.Unmarshal([]byte(rawValue), &value); err != nil {
		return contract.Response{}, internalError(err)
	}
	if !value.RequireConsent {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_request", "Consent not required")
	}
	claimed, err := p.consumeVerification(ctx.GoContext(), consentCode)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if claimed == nil {
		return contract.Response{}, oauthError(contract.StatusUnauthorized, "invalid_request", "Invalid code")
	}
	if !accept {
		return jsonResponse(contract.StatusOK, map[string]any{
			"redirectURI": value.RedirectURI + "?error=access_denied&error_description=User denied access",
		})
	}
	code, err := p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789")
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	value.RequireConsent = false
	encoded, err := json.Marshal(value)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	if _, err := p.createVerification(
		ctx.GoContext(), code, string(encoded), p.clock().Add(p.options.CodeExpiresIn),
	); err != nil {
		return contract.Response{}, internalError(err)
	}
	now := p.clock().UTC()
	if _, err := p.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{
		Model: "oauthConsent",
		Data: storage.Record{
			"clientId": value.ClientID, "userId": value.UserID,
			"scopes": strings.Join(value.Scope, " "), "consentGiven": true,
			"createdAt": now, "updatedAt": now,
		},
	}); err != nil {
		return contract.Response{}, internalError(err)
	}
	query := map[string]string{"code": code}
	if value.State != nil {
		query["state"] = *value.State
	}
	location, err := appendURLQuery(value.RedirectURI, query)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return jsonResponse(contract.StatusOK, map[string]any{"redirectURI": location})
}
