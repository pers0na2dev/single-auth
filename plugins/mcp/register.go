package mcp

import (
	"encoding/json"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

var allowedGrantTypes = map[string]struct{}{
	"authorization_code": {}, "implicit": {}, "password": {},
	"client_credentials": {}, "refresh_token": {},
	"urn:ietf:params:oauth:grant-type:jwt-bearer":   {},
	"urn:ietf:params:oauth:grant-type:saml2-bearer": {},
}

var allowedResponseTypes = map[string]struct{}{"code": {}, "token": {}}

func (p *plugin) register(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeBody(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	if body == nil {
		return contract.Response{}, validationError("request body is required")
	}
	addProtocolCORS(ctx)

	redirectURIs, redirectsExist, err := bodyStringSlice(body, "redirect_uris")
	if err != nil {
		return contract.Response{}, err
	}
	if !redirectsExist {
		return contract.Response{}, validationError("redirect_uris is required")
	}
	for _, redirectURI := range redirectURIs {
		if !isSafeURLScheme(redirectURI) {
			return contract.Response{}, validationError("redirect_uri cannot use a javascript:, data:, or vbscript: scheme")
		}
	}

	authMethod, exists, err := optionalBodyString(body, "token_endpoint_auth_method")
	if err != nil {
		return contract.Response{}, err
	}
	if !exists || authMethod == "" {
		authMethod = "client_secret_basic"
	}
	switch authMethod {
	case "none", "client_secret_basic", "client_secret_post":
	default:
		return contract.Response{}, validationError("invalid token_endpoint_auth_method")
	}

	grantTypes, grantsExist, err := bodyStringSlice(body, "grant_types")
	if err != nil {
		return contract.Response{}, err
	}
	if !grantsExist {
		grantTypes = []string{"authorization_code"}
	}
	for _, grant := range grantTypes {
		if _, ok := allowedGrantTypes[grant]; !ok {
			return contract.Response{}, validationError("invalid grant_types")
		}
	}
	responseTypes, responsesExist, err := bodyStringSlice(body, "response_types")
	if err != nil {
		return contract.Response{}, err
	}
	if !responsesExist {
		responseTypes = []string{"code"}
	}
	for _, responseType := range responseTypes {
		if _, ok := allowedResponseTypes[responseType]; !ok {
			return contract.Response{}, validationError("invalid response_types")
		}
	}

	if (contains(grantTypes, "authorization_code") || contains(grantTypes, "implicit")) && len(redirectURIs) == 0 {
		return contract.Response{}, oauthError(
			contract.StatusBadRequest, "invalid_redirect_uri",
			"Redirect URIs are required for authorization_code and implicit grant types",
		)
	}
	if grantsExist && responsesExist {
		if contains(grantTypes, "authorization_code") && !contains(responseTypes, "code") {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_client_metadata",
				"When 'authorization_code' grant type is used, 'code' response type must be included",
			)
		}
		if contains(grantTypes, "implicit") && !contains(responseTypes, "token") {
			return contract.Response{}, oauthError(
				contract.StatusBadRequest, "invalid_client_metadata",
				"When 'implicit' grant type is used, 'token' response type must be included",
			)
		}
	}

	clientID := ""
	if p.options.OIDCConfig.GenerateClientID != nil {
		clientID = p.options.OIDCConfig.GenerateClientID()
	}
	if clientID == "" {
		clientID, err = p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	clientSecret := ""
	if p.options.OIDCConfig.GenerateClientSecret != nil {
		clientSecret = p.options.OIDCConfig.GenerateClientSecret()
	}
	if clientSecret == "" {
		clientSecret, err = p.randomString(32, "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		if err != nil {
			return contract.Response{}, internalError(err)
		}
	}
	clientType := "web"
	if authMethod == "none" {
		clientType = "public"
		clientSecret = ""
	}

	now := p.clock().UTC()
	record := storage.Record{
		"clientId": clientID, "redirectUrls": strings.Join(redirectURIs, ","),
		"type": clientType, "disabled": false, "createdAt": now, "updatedAt": now,
	}
	if clientType != "public" {
		record["clientSecret"] = clientSecret
	}
	if name, present, fieldErr := optionalBodyString(body, "client_name"); fieldErr != nil {
		return contract.Response{}, fieldErr
	} else if present {
		record["name"] = name
	}
	if icon, present, fieldErr := optionalBodyString(body, "logo_uri"); fieldErr != nil {
		return contract.Response{}, fieldErr
	} else if present {
		record["icon"] = icon
	}
	if metadata, present := body["metadata"]; present && metadata != nil {
		object, ok := metadata.(map[string]any)
		if !ok {
			return contract.Response{}, validationError("metadata must be an object")
		}
		encoded, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			return contract.Response{}, validationError("metadata must be JSON serializable")
		}
		record["metadata"] = string(encoded)
	}
	if p.options.Runtime.ResolveSession != nil {
		session, sessionErr := p.options.Runtime.ResolveSession(ctx, false)
		if sessionErr != nil {
			return contract.Response{}, sessionErr
		}
		if session != nil {
			if userID, ok := recordString(session.Session, "userId"); ok && userID != "" {
				record["userId"] = userID
			}
		}
	}
	if _, err := p.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{
		Model: "oauthApplication", Data: record,
	}); err != nil {
		return contract.Response{}, internalError(err)
	}

	response := map[string]any{
		"client_id":                  clientID,
		"client_id_issued_at":        now.Unix(),
		"redirect_uris":              redirectURIs,
		"token_endpoint_auth_method": authMethod,
		"grant_types":                grantTypes,
		"response_types":             responseTypes,
	}
	for _, field := range []string{
		"client_name", "client_uri", "logo_uri", "scope", "contacts", "tos_uri",
		"policy_uri", "jwks_uri", "jwks", "software_id", "software_version",
		"software_statement", "metadata",
	} {
		if value, present := body[field]; present && value != nil {
			response[field] = value
		}
	}
	if clientType != "public" {
		response["client_secret"] = clientSecret
		response["client_secret_expires_at"] = 0
	}
	result, err := jsonResponse(201, response)
	if err != nil {
		return contract.Response{}, internalError(err)
	}
	return result.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
