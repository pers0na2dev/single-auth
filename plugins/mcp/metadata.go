package mcp

import (
	"errors"
	"net/url"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// ProviderMetadata returns the OAuth/OIDC discovery document advertised by
// single-auth's MCP plugin. Override entries are applied last.
func ProviderMetadata(issuer, authBaseURL string, override map[string]any) (map[string]any, error) {
	if issuer == "" || authBaseURL == "" {
		return nil, errors.New("issuer or baseURL is not set. If you're the app developer, please make sure to set the `baseURL` in your auth config.")
	}
	metadata := map[string]any{
		"issuer":                   issuer,
		"authorization_endpoint":   authBaseURL + AuthorizePath,
		"token_endpoint":           authBaseURL + TokenPath,
		"userinfo_endpoint":        authBaseURL + "/mcp/userinfo",
		"jwks_uri":                 authBaseURL + "/mcp/jwks",
		"registration_endpoint":    authBaseURL + RegisterPath,
		"scopes_supported":         []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		"grant_types_supported":    []string{"authorization_code", "refresh_token"},
		"acr_values_supported": []string{
			"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
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

// ProtectedResourceMetadata returns RFC 9728 metadata for the protected MCP
// resource.
func ProtectedResourceMetadata(authBaseURL, resource string, oidcMetadata map[string]any) (map[string]any, error) {
	parsed, err := url.Parse(authBaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		if err == nil {
			err = errors.New("invalid auth base URL")
		}
		return nil, err
	}
	origin := parsed.Scheme + "://" + parsed.Host
	if resource == "" {
		resource = origin
	}
	jwksURI := authBaseURL + "/mcp/jwks"
	if value, ok := oidcMetadata["jwks_uri"].(string); ok {
		jwksURI = value
	}
	var scopes any = []string{"openid", "profile", "email", "offline_access"}
	if value, exists := oidcMetadata["scopes_supported"]; exists {
		scopes = value
	}
	return map[string]any{
		"resource":                              resource,
		"authorization_servers":                 []string{origin},
		"jwks_uri":                              jwksURI,
		"scopes_supported":                      scopes,
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{"RS256"},
	}, nil
}

func (p *plugin) discovery(ctx *engine.Context) (contract.Response, error) {
	baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return jsonResponse(contract.StatusOK, nil)
	}
	metadata, err := ProviderMetadata(p.options.Runtime.Issuer, baseURL, p.options.OIDCConfig.Metadata)
	if err != nil {
		// The frozen endpoint intentionally catches provider metadata errors and
		// returns JSON null rather than propagating a 500.
		return jsonResponse(contract.StatusOK, nil)
	}
	return jsonResponse(contract.StatusOK, metadata)
}

func (p *plugin) protectedResource(ctx *engine.Context) (contract.Response, error) {
	baseURL, err := p.options.Runtime.ResolveBaseURL(ctx.Request())
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	metadata, err := ProtectedResourceMetadata(baseURL, p.options.Resource, p.options.OIDCConfig.Metadata)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return jsonResponse(contract.StatusOK, metadata)
}
