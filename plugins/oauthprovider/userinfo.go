package oauthprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const UserInfoPath = "/oauth2/userinfo"

// ErrInvalidJWTAccessToken tells the shared access-token validator to continue
// with opaque-token lookup. Other verifier errors are treated as internal
// failures, matching single-auth's APIError-versus-Error distinction.
var ErrInvalidJWTAccessToken = errors.New("oauthprovider: invalid JWT access token")

// UserInfoJWTValidator verifies a JWT access token and returns its RFC 7662
// claims. It must return ErrInvalidJWTAccessToken when the input is not a JWT
// issued by this provider.
type UserInfoJWTValidator func(*engine.Context, string) (map[string]any, error)

// UserInfoCustomClaims adds application claims after the normal OIDC claims
// have been selected. Custom values intentionally override normal values.
type UserInfoCustomClaims func(
	context.Context,
	storage.Record,
	[]string,
	map[string]any,
) (map[string]any, error)

// UserInfoSubjectResolver implements pairwise subject identifiers. The client
// ID comes from client_id or azp on the validated access-token claims.
type UserInfoSubjectResolver func(
	context.Context,
	string,
	string,
) (string, error)

// UserInfoOptions configures single-auth's OIDC /userinfo endpoint.
type UserInfoOptions struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	ValidateJWT       UserInfoJWTValidator
	OpaqueTokenPrefix string
	StoredToken       func(context.Context, string) (string, error)
	CustomClaims      UserInfoCustomClaims
	ResolveSubject    UserInfoSubjectResolver
}

type userInfoEndpoint struct {
	options UserInfoOptions
}

// NewUserInfoPlugin constructs the transport-neutral OAuth Provider userinfo
// endpoint. The descriptor is served unchanged by net/http, fasthttp, Fiber,
// and direct API dispatch.
func NewUserInfoPlugin(options UserInfoOptions) (engine.Plugin, error) {
	if options.Adapter == nil {
		return engine.Plugin{}, errors.New("oauthprovider: UserInfoOptions.Adapter is required")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	implementation := &userInfoEndpoint{options: options}
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: OAuthProviderSchema(),
		Endpoints: []engine.Endpoint{{
			Name: "oauth2UserInfo", Path: UserInfoPath,
			Methods:     []string{http.MethodGet, http.MethodPost},
			OperationID: "oauth2UserInfo", Handler: implementation.userInfo,
		}},
	}, nil
}

func (endpoint *userInfoEndpoint) adapter(ctx context.Context) storage.TransactionAdapter {
	if endpoint.options.AdapterForContext != nil {
		if adapter := endpoint.options.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return endpoint.options.Adapter
}

func (endpoint *userInfoEndpoint) userInfo(ctx *engine.Context) (contract.Response, error) {
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	token := authorization
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}
	if token == "" {
		return userInfoError(
			contract.StatusUnauthorized,
			"invalid_request",
			"authorization header not found",
		)
	}

	claims, err := endpoint.validateAccessToken(ctx, token)
	if err != nil {
		var protocol *contract.APIError
		if errors.As(err, &protocol) {
			return contract.ResponseFromError(protocol), protocol
		}
		return userInfoInternal(err)
	}
	scopes := splitUserInfoSpaces(claimString(claims["scope"]))
	if !containsUserInfoString(scopes, "openid") {
		return userInfoError(
			contract.StatusBadRequest,
			"invalid_scope",
			"Missing required scope",
		)
	}
	userID := claimString(claims["sub"])
	if userID == "" {
		return userInfoError(contract.StatusBadRequest, "invalid_request", "user not found")
	}
	user, err := endpoint.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil {
		return userInfoInternal(err)
	}
	if user == nil {
		return userInfoError(contract.StatusBadRequest, "invalid_request", "user not found")
	}

	result := UserNormalClaims(user, scopes)
	if endpoint.options.ResolveSubject != nil {
		clientID := claimString(claims["client_id"])
		if clientID == "" {
			clientID = claimString(claims["azp"])
		}
		if clientID != "" {
			subject, resolveErr := endpoint.options.ResolveSubject(
				ctx.GoContext(), userID, clientID,
			)
			if resolveErr != nil {
				return userInfoInternal(resolveErr)
			}
			result["sub"] = subject
		}
	}
	if endpoint.options.CustomClaims != nil && len(scopes) > 0 {
		additional, customErr := endpoint.options.CustomClaims(
			ctx.GoContext(), cloneUserInfoRecord(user), append([]string(nil), scopes...), cloneUserInfoMap(claims),
		)
		if customErr != nil {
			return userInfoInternal(customErr)
		}
		for key, value := range additional {
			result[key] = value
		}
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

func (endpoint *userInfoEndpoint) validateAccessToken(
	ctx *engine.Context,
	token string,
) (map[string]any, error) {
	if endpoint.options.ValidateJWT != nil {
		claims, err := endpoint.options.ValidateJWT(ctx, token)
		switch {
		case err == nil && claims != nil:
			return cloneUserInfoMap(claims), nil
		case err != nil && !errors.Is(err, ErrInvalidJWTAccessToken):
			return nil, err
		}
	}

	lookupToken := token
	if endpoint.options.OpaqueTokenPrefix != "" {
		if !strings.HasPrefix(lookupToken, endpoint.options.OpaqueTokenPrefix) {
			return nil, invalidAccessTokenError()
		}
		lookupToken = strings.TrimPrefix(lookupToken, endpoint.options.OpaqueTokenPrefix)
	}
	if endpoint.options.StoredToken != nil {
		var err error
		lookupToken, err = endpoint.options.StoredToken(ctx.GoContext(), lookupToken)
		if err != nil {
			return nil, err
		}
	}
	record, err := endpoint.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthAccessToken", Where: []storage.Where{{Field: "token", Value: lookupToken}},
	})
	if err != nil {
		return nil, err
	}
	if record == nil {
		return nil, invalidAccessTokenError()
	}
	expiresAt, ok := userInfoTime(record["expiresAt"])
	if !ok || expiresAt.Before(endpoint.options.Clock()) {
		return map[string]any{"active": false}, nil
	}
	clientID := claimString(record["clientId"])
	if clientID != "" {
		client, findErr := endpoint.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
			Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
		})
		if findErr != nil {
			return nil, findErr
		}
		if client == nil || userInfoBool(client["disabled"]) {
			return map[string]any{"active": false}, nil
		}
	}
	return map[string]any{
		"active":    true,
		"client_id": clientID,
		"sub":       claimString(record["userId"]),
		"scope":     strings.Join(userInfoStrings(record["scopes"]), " "),
		"exp":       expiresAt.Unix(),
	}, nil
}

// UserNormalClaims selects single-auth's standard OIDC claims for scopes.
func UserNormalClaims(user storage.Record, scopes []string) map[string]any {
	result := make(map[string]any)
	if id, exists := userInfoOptionalString(user, "id"); exists {
		result["sub"] = id
	}
	if containsUserInfoString(scopes, "profile") {
		name, nameExists := userInfoOptionalString(user, "name")
		if nameExists {
			result["name"] = name
		}
		if image, exists := userInfoOptionalString(user, "image"); exists {
			result["picture"] = image
		}
		parts := splitUserInfoName(name)
		if len(parts) > 1 {
			result["given_name"] = strings.Join(parts[:len(parts)-1], " ")
			result["family_name"] = parts[len(parts)-1]
		}
	}
	if containsUserInfoString(scopes, "email") {
		if email, exists := userInfoOptionalString(user, "email"); exists {
			result["email"] = email
		}
		result["email_verified"] = userInfoBool(user["emailVerified"])
	}
	return result
}

func userInfoError(status int, code, description string) (contract.Response, error) {
	err := contract.NewAPIError(status, strings.ToUpper(code), description).WithWireBody(map[string]any{
		"error": code, "error_description": description,
	})
	return contract.ResponseFromError(err), err
}

func invalidAccessTokenError() *contract.APIError {
	return contract.NewAPIError(
		contract.StatusBadRequest, "INVALID_REQUEST", "Invalid access token",
	).WithWireBody(map[string]any{
		"error": "invalid_request", "error_description": "Invalid access token",
	})
}

func userInfoInternal(cause error) (contract.Response, error) {
	err := contract.NewAPIError(
		contract.StatusInternalServerError,
		"INTERNAL_SERVER_ERROR",
		"Internal Server Error",
	).WithCause(fmt.Errorf("oauthprovider userinfo: %w", cause))
	return contract.ResponseFromError(err), err
}

func claimString(value any) string {
	result, _ := value.(string)
	return result
}

func userInfoBool(value any) bool {
	result, _ := value.(bool)
	return result
}

func userInfoStrings(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func userInfoTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed, true
	case *time.Time:
		if typed != nil {
			return *typed, true
		}
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		return parsed, err == nil
	}
	return time.Time{}, false
}

func containsUserInfoString(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func splitUserInfoSpaces(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, " ")
}

func splitUserInfoName(value string) []string {
	parts := strings.Split(value, " ")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func userInfoOptionalString(record storage.Record, key string) (string, bool) {
	value, exists := record[key]
	if !exists || value == nil {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func cloneUserInfoRecord(source storage.Record) storage.Record {
	return storage.Record(cloneUserInfoMap(source))
}

func cloneUserInfoMap(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
