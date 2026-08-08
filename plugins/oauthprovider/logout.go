package oauthprovider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	// EndSessionPath is the OAuth provider RP-Initiated Logout route from
	// single-auth 1.6.26. It intentionally differs from the deprecated
	// oidc-provider plugin's /oauth2/endsession spelling.
	EndSessionPath = "/oauth2/end-session"
	PluginID       = "oauth-provider"
	Version        = "1.6.26"
)

// LogoutJWTVerifier verifies the compact JWS signature used by the configured
// JWT plugin and returns its claims. Claim validation that is specific to
// RP-Initiated Logout (issuer, audience and sid) remains in this package.
type LogoutJWTVerifier func(*engine.Context, string) (map[string]any, error)

// LogoutRuntime is the persistence and cryptographic surface needed by the
// RP-Initiated Logout endpoint.
type LogoutRuntime struct {
	Adapter             storage.Adapter
	AdapterForContext   func(context.Context) storage.TransactionAdapter
	Issuer              string
	ResolveBaseURL      func(contract.Request) (string, error)
	VerifyJWT           LogoutJWTVerifier
	DecryptClientSecret func(context.Context, string) (string, error)
	DeleteSession       func(context.Context, string) error
}

// LogoutOptions controls the two ID-token verification modes supported by the
// upstream OAuth provider.
type LogoutOptions struct {
	DisableJWTPlugin bool
	Runtime          LogoutRuntime
}

type logoutEndpoint struct {
	disableJWTPlugin bool
	runtime          LogoutRuntime
}

type logoutClient struct {
	clientID               string
	clientSecret           string
	disabled               bool
	enableEndSession       bool
	postLogoutRedirectURIs []string
}

// NewLogoutPlugin constructs the transport-neutral production endpoint. The
// returned descriptor can be served by net/http, fasthttp and Fiber through
// the standard single-auth transports.
func NewLogoutPlugin(options LogoutOptions) (engine.Plugin, error) {
	if options.Runtime.Adapter == nil {
		return engine.Plugin{}, errors.New("oauthprovider: LogoutRuntime.Adapter is required")
	}
	if !options.DisableJWTPlugin && options.Runtime.VerifyJWT == nil {
		return engine.Plugin{}, errors.New("oauthprovider: LogoutRuntime.VerifyJWT is required when the JWT plugin is enabled")
	}
	implementation := &logoutEndpoint{
		disableJWTPlugin: options.DisableJWTPlugin,
		runtime:          options.Runtime,
	}
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: OAuthProviderSchema(),
		Endpoints: []engine.Endpoint{{
			Name: "oauth2EndSession", Path: EndSessionPath,
			Methods: []string{http.MethodGet}, OperationID: "oauth2EndSession",
			Handler: implementation.endSession,
		}},
	}, nil
}

func (endpoint *logoutEndpoint) adapter(ctx context.Context) storage.TransactionAdapter {
	if endpoint.runtime.AdapterForContext != nil {
		if adapter := endpoint.runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return endpoint.runtime.Adapter
}

func (endpoint *logoutEndpoint) endSession(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return logoutError(contract.StatusBadRequest, "invalid_request", "invalid query")
	}
	idTokenHint := query.Get("id_token_hint")
	clientID := query.Get("client_id")
	postLogoutRedirectURI := query.Get("post_logout_redirect_uri")
	state := query.Get("state")

	if clientID == "" {
		unverified, decodeErr := decodeCompactJWSPayload(idTokenHint)
		if decodeErr != nil {
			return logoutError(contract.StatusUnauthorized, "invalid_token", "invalid id token")
		}
		clientID = firstAudience(unverified["aud"])
		if clientID == "" {
			return logoutError(contract.StatusInternalServerError, "invalid_request", "id token missing audience")
		}
	}

	client, err := endpoint.findClient(ctx.GoContext(), clientID)
	if err != nil {
		return logoutInternal(err)
	}
	if client == nil {
		return logoutError(contract.StatusBadRequest, "invalid_client", "client doesn't exist")
	}
	if client.disabled {
		return logoutError(contract.StatusBadRequest, "invalid_client", "client is disabled")
	}
	if !client.enableEndSession {
		return logoutError(contract.StatusUnauthorized, "invalid_client", "client unable to logout")
	}

	claims, err := endpoint.verifyIDToken(ctx, idTokenHint, client)
	if err != nil {
		return logoutError(contract.StatusUnauthorized, "invalid_token", "invalid id token")
	}
	issuer, err := endpoint.issuer(ctx.Request())
	if err != nil {
		return logoutInternal(err)
	}
	claimIssuer, _ := claims["iss"].(string)
	if claimIssuer != issuer {
		return logoutError(contract.StatusInternalServerError, "invalid_request", "invalid issuer")
	}
	audience := audiences(claims["aud"])
	if len(audience) == 0 {
		return logoutError(contract.StatusInternalServerError, "invalid_request", "id token missing audience")
	}
	if query.Get("client_id") != "" && !containsLogoutString(audience, clientID) {
		return logoutError(contract.StatusBadRequest, "invalid_request", "audience mismatch")
	}
	sessionID, _ := claims["sid"].(string)
	if sessionID == "" {
		return logoutError(contract.StatusInternalServerError, "invalid_request", "id token missing session")
	}

	// single-auth treats an already-removed or otherwise undeletable session as
	// a successful idempotent logout.
	endpoint.deleteSession(ctx.GoContext(), sessionID)

	if postLogoutRedirectURI != "" && containsLogoutString(
		client.postLogoutRedirectURIs,
		postLogoutRedirectURI,
	) {
		redirectURI, parseErr := url.Parse(postLogoutRedirectURI)
		if parseErr == nil {
			if state != "" {
				parameters := redirectURI.Query()
				parameters.Set("state", state)
				redirectURI.RawQuery = parameters.Encode()
			}
			return contract.NewResponse(
				contract.StatusFound,
				contract.NewHeaders(contract.HeaderField{Name: "Location", Value: redirectURI.String()}),
				nil,
			), nil
		}
	}
	return contract.JSONResponse(contract.StatusOK, nil)
}

func (endpoint *logoutEndpoint) issuer(request contract.Request) (string, error) {
	if endpoint.runtime.Issuer != "" {
		return endpoint.runtime.Issuer, nil
	}
	if endpoint.runtime.ResolveBaseURL != nil {
		return endpoint.runtime.ResolveBaseURL(request)
	}
	if request.Scheme() == "" || request.Host() == "" {
		return "", errors.New("oauthprovider: logout issuer is unavailable")
	}
	return request.Scheme() + "://" + request.Host(), nil
}

func (endpoint *logoutEndpoint) findClient(ctx context.Context, clientID string) (*logoutClient, error) {
	record, err := endpoint.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil || record == nil {
		return nil, err
	}
	client := &logoutClient{clientID: clientID}
	client.clientSecret, _ = logoutString(record["clientSecret"])
	client.disabled, _ = record["disabled"].(bool)
	client.enableEndSession, _ = record["enableEndSession"].(bool)
	client.postLogoutRedirectURIs = logoutStrings(record["postLogoutRedirectUris"])
	return client, nil
}

func (endpoint *logoutEndpoint) verifyIDToken(
	ctx *engine.Context,
	token string,
	client *logoutClient,
) (map[string]any, error) {
	if !endpoint.disableJWTPlugin {
		return endpoint.runtime.VerifyJWT(ctx, token)
	}
	if client.clientSecret == "" {
		return nil, errors.New("oauthprovider: client secret is missing")
	}
	secret := client.clientSecret
	if endpoint.runtime.DecryptClientSecret != nil {
		var err error
		secret, err = endpoint.runtime.DecryptClientSecret(ctx.GoContext(), secret)
		if err != nil {
			return nil, err
		}
	}
	return verifyLogoutHS256(token, secret)
}

func (endpoint *logoutEndpoint) deleteSession(ctx context.Context, sessionID string) {
	session, err := endpoint.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "session", Where: []storage.Where{{Field: "id", Value: sessionID}},
	})
	if err != nil {
		return
	}
	if token, ok := logoutString(session["token"]); ok && token != "" && endpoint.runtime.DeleteSession != nil {
		_ = endpoint.runtime.DeleteSession(ctx, token)
		return
	}
	_ = endpoint.adapter(ctx).Delete(ctx, storage.DeleteParams{
		Model: "session", Where: []storage.Where{{Field: "id", Value: sessionID}},
	})
}

// SanitizeDynamicRegistration removes the admin-only enable_end_session input
// while retaining ordinary dynamic-registration metadata. single-auth never
// permits a self-registered RP to grant itself logout authority.
func SanitizeDynamicRegistration(input map[string]any) map[string]any {
	result := make(map[string]any, len(input))
	for key, value := range input {
		if key == "enable_end_session" || key == "enableEndSession" {
			continue
		}
		result[key] = cloneRegistrationValue(value)
	}
	return result
}

func cloneRegistrationValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = cloneRegistrationValue(item)
		}
		return result
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			result[key] = cloneRegistrationValue(item)
		}
		return result
	default:
		return typed
	}
}

func verifyLogoutHS256(token, secret string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oauthprovider: malformed id token")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header struct {
		Algorithm string `json:"alg"`
	}
	if json.Unmarshal(headerBytes, &header) != nil || header.Algorithm != "HS256" {
		return nil, errors.New("oauthprovider: invalid id token algorithm")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return nil, errors.New("oauthprovider: invalid id token signature")
	}
	return decodeCompactJWSPayload(token)
}

func decodeCompactJWSPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oauthprovider: malformed id token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payloadBytes)))
	decoder.UseNumber()
	payload := make(map[string]any)
	if err := decoder.Decode(&payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func firstAudience(value any) string {
	values := audiences(value)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func audiences(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed != "" {
			return []string{typed}
		}
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok {
				result = append(result, value)
			}
		}
		return result
	}
	return nil
}

func logoutString(value any) (string, bool) {
	if value == nil {
		return "", false
	}
	result, ok := value.(string)
	return result, ok
}

func logoutStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok {
				result = append(result, value)
			}
		}
		return result
	case string:
		var result []string
		if strings.HasPrefix(strings.TrimSpace(typed), "[") && json.Unmarshal([]byte(typed), &result) == nil {
			return result
		}
	}
	return nil
}

func containsLogoutString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func logoutError(status int, code, description string) (contract.Response, error) {
	err := contract.NewAPIError(status, strings.ToUpper(code), description).WithWireBody(map[string]any{
		"error": code, "error_description": description,
	})
	return contract.ResponseFromError(err), err
}

func logoutInternal(cause error) (contract.Response, error) {
	err := contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(fmt.Errorf("oauthprovider logout: %w", cause))
	return contract.ResponseFromError(err), err
}
