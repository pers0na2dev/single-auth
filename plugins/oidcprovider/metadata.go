package oidcprovider

import (
	"errors"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// ProviderMetadata returns the frozen OpenID Provider discovery document.
// Override entries are applied last, exactly like the TypeScript object spread.
func ProviderMetadata(issuer, authBaseURL string, useJWTPlugin bool, override map[string]any) (map[string]any, error) {
	if issuer == "" || authBaseURL == "" {
		return nil, errors.New("issuer or baseURL is not set")
	}
	supportedAlgorithms := []string{"HS256"}
	if useJWTPlugin {
		supportedAlgorithms = []string{"RS256", "EdDSA"}
	}
	metadata := map[string]any{
		"issuer":                   issuer,
		"authorization_endpoint":   authBaseURL + AuthorizePath,
		"token_endpoint":           authBaseURL + TokenPath,
		"userinfo_endpoint":        authBaseURL + UserInfoPath,
		"jwks_uri":                 authBaseURL + "/jwks",
		"registration_endpoint":    authBaseURL + RegistrationPath,
		"end_session_endpoint":     authBaseURL + EndSessionPath,
		"scopes_supported":         []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		"acr_values_supported": []string{
			"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": supportedAlgorithms,
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic", "client_secret_post", "none",
		},
		"code_challenge_methods_supported": []string{"S256"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "nbf", "iat", "jti",
			"email", "email_verified", "name",
		},
	}
	for key, value := range override {
		metadata[key] = value
	}
	return metadata, nil
}

func (p *plugin) discovery(ctx *engine.Context) (contract.Response, error) {
	baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	metadata, err := ProviderMetadata(p.resolveIssuer(baseURL), baseURL, p.options.UseJWTPlugin, p.options.Metadata)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return jsonResponse(contract.StatusOK, metadata)
}
