package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

// NewFactory returns a reusable API-key plugin factory.
func NewFactory(options Options) *Plugin {
	return &Plugin{options: snapshotOptions(options)}
}

// MustNewFactory is NewFactory for declarative application setup.
func MustNewFactory(options Options) *Plugin { return NewFactory(options) }

func (*Plugin) PluginID() string { return "api-key" }

func (plugin *Plugin) Schema() (storage.Schema, error) {
	if plugin == nil {
		return storage.Schema{}, errors.New("apikey: plugin is nil")
	}
	return Schema(plugin.options)
}

func (plugin *Plugin) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if plugin == nil {
		return engine.Plugin{}, errors.New("apikey: plugin is nil")
	}
	options := snapshotOptions(plugin.options)
	options.Runtime.Adapter = host.Adapter
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.HasPlugin = host.HasPlugin
	options.Runtime.SerializeUser = host.SerializeUser
	options.Runtime.SerializeSession = host.SerializeSession
	resolveSession := func(ctx *engine.Context, mode singleauth.PluginSessionMode) (*SessionState, error) {
		state, err := host.ResolveSession(ctx, mode)
		if err != nil {
			if statusError, ok := contract.AsAPIError(err); ok && statusError.Code == "UNAUTHORIZED" {
				return nil, nil
			}
			return nil, err
		}
		if state == nil {
			return nil, nil
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.ResolveSession = func(ctx *engine.Context) (*SessionState, error) {
		return resolveSession(ctx, singleauth.PluginSessionOptional)
	}
	options.Runtime.ResolveAuthoritativeSession = func(ctx *engine.Context) (*SessionState, error) {
		return resolveSession(ctx, singleauth.PluginSessionAuthoritative)
	}
	service, err := NewService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	plugin.mu.Lock()
	if plugin.service != nil {
		plugin.mu.Unlock()
		return engine.Plugin{}, errors.New("apikey: plugin factory is already bound")
	}
	plugin.service = service
	plugin.mu.Unlock()
	return service.descriptor(), nil
}

// New constructs a standalone engine plugin from explicit runtime services.
func New(options Options) (engine.Plugin, error) {
	service, err := NewService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return service.descriptor(), nil
}

// MustNew is New for static standalone setup.
func MustNew(options Options) engine.Plugin {
	plugin, err := New(options)
	if err != nil {
		panic(err)
	}
	return plugin
}

func snapshotOptions(source Options) Options {
	result := source
	result.Configurations = make([]Configuration, len(source.Configurations))
	for index, configuration := range source.Configurations {
		result.Configurations[index] = configuration
		result.Configurations[index].StoreStartingCharacters = cloneBool(configuration.StoreStartingCharacters)
		result.Configurations[index].RateLimitEnabled = cloneBool(configuration.RateLimitEnabled)
		result.Configurations[index].DefaultPermissions = clonePermissions(configuration.DefaultPermissions)
		result.Configurations[index].APIKeyHeaders = append([]string(nil), configuration.APIKeyHeaders...)
	}
	result.Organization = snapshotOrganizationAuthorization(source.Organization)
	result.Schema = source.Schema.Clone()
	return result
}

func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (service *Service) descriptor() engine.Plugin {
	schema, _ := Schema(service.options)
	return engine.Plugin{
		ID: "api-key", Version: Version, Schema: schema,
		Endpoints: []engine.Endpoint{
			{Name: "createApiKey", Path: "/api-key/create", Methods: []string{http.MethodPost}, OperationID: "createApiKey", Handler: service.createEndpoint},
			{Name: "verifyApiKey", ServerOnly: true, Methods: []string{http.MethodPost}, OperationID: "verifyApiKey", Handler: service.verifyEndpoint},
			{Name: "getApiKey", Path: "/api-key/get", Methods: []string{http.MethodGet}, OperationID: "getApiKey", Handler: service.getEndpoint},
			{Name: "updateApiKey", Path: "/api-key/update", Methods: []string{http.MethodPost}, OperationID: "updateApiKey", Handler: service.updateEndpoint},
			{Name: "deleteApiKey", Path: "/api-key/delete", Methods: []string{http.MethodPost}, OperationID: "deleteApiKey", Handler: service.deleteEndpoint},
			{Name: "listApiKeys", Path: "/api-key/list", Methods: []string{http.MethodGet}, OperationID: "listApiKeys", Handler: service.listEndpoint},
		},
		Hooks: engine.Hooks{Before: []engine.BeforeHook{{
			Name:    "api-key-session",
			Matcher: service.apiKeySessionMatcher,
			Handler: service.apiKeySessionHook,
		}}},
		ErrorCodes: pluginErrorCodes(),
	}
}

func (plugin *Plugin) boundService() (*Service, error) {
	if plugin == nil {
		return nil, errors.New("apikey: plugin is nil")
	}
	plugin.mu.RLock()
	service := plugin.service
	plugin.mu.RUnlock()
	if service == nil {
		return nil, errors.New("apikey: plugin is not bound to single-auth")
	}
	return service, nil
}

func (plugin *Plugin) Create(ctx context.Context, input CreateInput) (APIKey, error) {
	service, err := plugin.boundService()
	if err != nil {
		return APIKey{}, err
	}
	return service.Create(ctx, input)
}

func (plugin *Plugin) Get(ctx context.Context, input GetInput) (APIKey, error) {
	service, err := plugin.boundService()
	if err != nil {
		return APIKey{}, err
	}
	return service.Get(ctx, input)
}

func (plugin *Plugin) List(ctx context.Context, input ListInput) (ListResult, error) {
	service, err := plugin.boundService()
	if err != nil {
		return ListResult{}, err
	}
	return service.List(ctx, input)
}

func (plugin *Plugin) Update(ctx context.Context, input UpdateInput) (APIKey, error) {
	service, err := plugin.boundService()
	if err != nil {
		return APIKey{}, err
	}
	return service.Update(ctx, input)
}

func (plugin *Plugin) Delete(ctx context.Context, input DeleteInput) error {
	service, err := plugin.boundService()
	if err != nil {
		return err
	}
	return service.Delete(ctx, input)
}

func (plugin *Plugin) Verify(ctx context.Context, input VerifyInput) (VerifyResult, error) {
	service, err := plugin.boundService()
	if err != nil {
		return VerifyResult{}, err
	}
	return service.Verify(ctx, input), nil
}

type createBody struct {
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Prefix              string              `json:"prefix"`
	ExpiresIn           *int64              `json:"expiresIn"`
	Remaining           *int64              `json:"remaining"`
	RefillAmount        *int64              `json:"refillAmount"`
	RefillInterval      *int64              `json:"refillInterval"`
	Metadata            any                 `json:"metadata"`
	Permissions         map[string][]string `json:"permissions"`
	RateLimitMax        *int64              `json:"rateLimitMax"`
	RateLimitTimeWindow *int64              `json:"rateLimitTimeWindow"`
	RateLimitEnabled    *bool               `json:"rateLimitEnabled"`
	UserID              string              `json:"userId"`
	OrganizationID      string              `json:"organizationId"`
}

func (service *Service) createEndpoint(ctx *engine.Context) (contract.Response, error) {
	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	var body createBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	if !ctx.IsDirect() {
		if _, supplied := raw["userId"]; supplied {
			return contract.Response{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
		if createUsesHTTPServerOnlyProperty(raw) {
			return contract.Response{}, apiError(contract.StatusBadRequest, ErrorServerOnlyProperty)
		}
	}
	actor, err := service.authoritativeEndpointActor(ctx, !ctx.IsDirect())
	if err != nil {
		return contract.Response{}, err
	}
	input := CreateInput{
		ConfigID: body.ConfigID, Name: body.Name, Prefix: body.Prefix,
		Remaining: body.Remaining, RefillAmount: body.RefillAmount,
		Metadata: body.Metadata, Permissions: body.Permissions,
		RateLimitMax: body.RateLimitMax, RateLimitEnabled: body.RateLimitEnabled,
		UserID: body.UserID, OrganizationID: body.OrganizationID, ActorUserID: actor,
	}
	if body.ExpiresIn != nil {
		duration := time.Duration(*body.ExpiresIn) * time.Second
		input.ExpiresIn = &duration
	}
	if body.RefillInterval != nil {
		duration := time.Duration(*body.RefillInterval) * time.Millisecond
		input.RefillInterval = &duration
	}
	if body.RateLimitTimeWindow != nil {
		duration := time.Duration(*body.RateLimitTimeWindow) * time.Millisecond
		input.RateLimitTimeWindow = &duration
	}
	created, err := service.Create(ctx.GoContext(), input)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, created)
}

func createUsesHTTPServerOnlyProperty(raw map[string]json.RawMessage) bool {
	for _, field := range []string{
		"refillAmount", "refillInterval", "rateLimitMax", "rateLimitTimeWindow",
		"rateLimitEnabled", "permissions",
	} {
		if _, supplied := raw[field]; supplied {
			return true
		}
	}
	remaining, supplied := raw["remaining"]
	return supplied && !bytes.Equal(bytes.TrimSpace(remaining), []byte("null"))
}

func (service *Service) getEndpoint(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters").WithCause(err)
	}
	actor, err := service.endpointActor(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	key, err := service.Get(ctx.GoContext(), GetInput{ID: query.Get("id"), ConfigID: query.Get("configId"), ActorUserID: actor})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, key)
}

func (service *Service) listEndpoint(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters").WithCause(err)
	}
	actor, err := service.endpointActor(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if actor == "" {
		return contract.Response{}, contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	}
	input := ListInput{ConfigID: query.Get("configId"), OrganizationID: query.Get("organizationId"), ActorUserID: actor}
	if value := query.Get("limit"); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters").WithCause(parseErr)
		}
		input.Limit = &parsed
	}
	if value := query.Get("offset"); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil {
			return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters").WithCause(parseErr)
		}
		input.Offset = &parsed
	}
	result, err := service.List(ctx.GoContext(), input)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, result)
}

type updateBody struct {
	KeyID               string              `json:"keyId"`
	ConfigID            string              `json:"configId"`
	Name                *string             `json:"name"`
	Enabled             *bool               `json:"enabled"`
	ExpiresIn           *float64            `json:"expiresIn"`
	Remaining           *float64            `json:"remaining"`
	RefillAmount        *float64            `json:"refillAmount"`
	RefillInterval      *float64            `json:"refillInterval"`
	Metadata            any                 `json:"metadata"`
	RateLimitEnabled    *bool               `json:"rateLimitEnabled"`
	RateLimitTimeWindow *float64            `json:"rateLimitTimeWindow"`
	RateLimitMax        *float64            `json:"rateLimitMax"`
	Permissions         map[string][]string `json:"permissions"`
	UserID              any                 `json:"userId"`
}

func (service *Service) updateEndpoint(ctx *engine.Context) (contract.Response, error) {
	raw := make(map[string]json.RawMessage)
	if err := json.Unmarshal(ctx.Request().Body(), &raw); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	if err := validateUpdateBody(raw); err != nil {
		return contract.Response{}, err
	}
	var body updateBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	hasRequestHeaders := !ctx.IsDirect() || directCallHasRequestHeaders(ctx.Request().Headers())
	actor, err := service.authoritativeEndpointActor(ctx, hasRequestHeaders)
	if err != nil {
		return contract.Response{}, err
	}
	userID := coerceUpdateUserID(body.UserID, raw)
	if actor == "" {
		actor = userID
	}
	if actor == "" || (userID != "" && actor != userID) {
		return contract.Response{}, apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
	}
	if hasRequestHeaders && updateUsesServerOnlyProperty(raw) {
		return contract.Response{}, apiError(contract.StatusBadRequest, ErrorServerOnlyProperty)
	}
	input := UpdateInput{
		KeyID: body.KeyID, ConfigID: body.ConfigID, ActorUserID: actor,
		Name: body.Name, Enabled: body.Enabled, Remaining: int64Pointer(body.Remaining),
		RefillAmount: int64Pointer(body.RefillAmount), Metadata: body.Metadata,
		RateLimitEnabled: body.RateLimitEnabled, RateLimitMax: int64Pointer(body.RateLimitMax),
		Permissions: body.Permissions,
	}
	_, input.MetadataSet = raw["metadata"]
	_, input.PermissionsSet = raw["permissions"]
	_, input.ExpiresInSet = raw["expiresIn"]
	expiresInExceedsDuration := false
	if body.ExpiresIn != nil {
		duration, exceedsDuration := durationFromFloat64(*body.ExpiresIn, time.Second)
		input.ExpiresIn = &duration
		expiresInExceedsDuration = exceedsDuration
	}
	if body.RefillInterval != nil {
		duration := time.Duration(*body.RefillInterval * float64(time.Millisecond))
		input.RefillInterval = &duration
	}
	if body.RateLimitTimeWindow != nil {
		duration := time.Duration(*body.RateLimitTimeWindow * float64(time.Millisecond))
		input.RateLimitTimeWindow = &duration
	}
	updated, err := service.update(ctx.GoContext(), input, expiresInExceedsDuration)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, updated)
}

func validateUpdateBody(raw map[string]json.RawMessage) error {
	keyID, supplied := raw["keyId"]
	if !supplied || !rawJSONHasType(keyID, "string") {
		return invalidUpdateBody()
	}
	for _, field := range []string{"configId", "name"} {
		if value, exists := raw[field]; exists && !rawJSONHasType(value, "string") {
			return invalidUpdateBody()
		}
	}
	for _, field := range []string{"enabled", "rateLimitEnabled"} {
		if value, exists := raw[field]; exists && !rawJSONHasType(value, "boolean") {
			return invalidUpdateBody()
		}
	}
	for _, field := range []string{
		"remaining", "refillAmount", "refillInterval", "rateLimitTimeWindow", "rateLimitMax",
	} {
		if value, exists := raw[field]; exists && !rawJSONHasType(value, "number") {
			return invalidUpdateBody()
		}
	}
	if expiresIn, exists := raw["expiresIn"]; exists && !rawJSONIsNull(expiresIn) && !rawJSONHasType(expiresIn, "number") {
		return invalidUpdateBody()
	}
	return nil
}

func rawJSONHasType(raw json.RawMessage, expected string) bool {
	if rawJSONIsNull(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	switch expected {
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "number":
		_, ok := value.(json.Number)
		return ok
	default:
		return false
	}
}

func rawJSONIsNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func invalidUpdateBody() *contract.APIError {
	return contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
}

func int64Pointer(value *float64) *int64 {
	if value == nil {
		return nil
	}
	converted := int64(*value)
	return &converted
}

func durationFromFloat64(value float64, unit time.Duration) (time.Duration, bool) {
	nanoseconds := value * float64(unit)
	switch {
	case math.IsNaN(nanoseconds):
		return 0, false
	case nanoseconds >= float64(math.MaxInt64):
		return time.Duration(math.MaxInt64), true
	case nanoseconds <= float64(math.MinInt64):
		return time.Duration(math.MinInt64), false
	default:
		return time.Duration(nanoseconds), false
	}
}

func coerceUpdateUserID(value any, raw map[string]json.RawMessage) string {
	if _, supplied := raw["userId"]; !supplied {
		return ""
	}
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return typed
	case bool:
		return strconv.FormatBool(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

func directCallHasRequestHeaders(headers contract.Headers) bool {
	for _, field := range headers.Fields() {
		if !strings.EqualFold(field.Name, "content-type") {
			return true
		}
	}
	return false
}

func updateUsesServerOnlyProperty(raw map[string]json.RawMessage) bool {
	for _, field := range []string{
		"refillAmount", "refillInterval", "rateLimitMax", "rateLimitTimeWindow",
		"rateLimitEnabled", "remaining", "permissions",
	} {
		if _, supplied := raw[field]; supplied {
			return true
		}
	}
	return false
}

type deleteBody struct {
	KeyID    string `json:"keyId"`
	ConfigID string `json:"configId"`
}

func (service *Service) deleteEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body deleteBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	actor, err := service.endpointActor(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	if err := service.Delete(ctx.GoContext(), DeleteInput{KeyID: body.KeyID, ConfigID: body.ConfigID, ActorUserID: actor}); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, map[string]bool{"success": true})
}

type verifyBody struct {
	Key         string              `json:"key"`
	ConfigID    string              `json:"configId"`
	Permissions map[string][]string `json:"permissions"`
}

func (service *Service) verifyEndpoint(ctx *engine.Context) (contract.Response, error) {
	var body verifyBody
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body").WithCause(err)
	}
	return contract.JSONResponse(contract.StatusOK, service.Verify(ctx.GoContext(), VerifyInput{
		Key: body.Key, ConfigID: body.ConfigID, Permissions: body.Permissions,
	}))
}

func (service *Service) apiKeySessionMatcher(ctx *engine.Context) (bool, error) {
	_, _, found := service.apiKeyFromRequest(ctx)
	return found, nil
}

func (service *Service) apiKeyFromRequest(ctx *engine.Context) (string, Configuration, bool) {
	if ctx == nil || ctx.IsDirect() {
		return "", Configuration{}, false
	}
	headers := ctx.Request().Headers()
	for _, config := range service.configurations {
		if !config.EnableSessionForAPIKeys {
			continue
		}
		for _, header := range config.APIKeyHeaders {
			if value, exists := headers.Get(header); exists && value != "" {
				return value, config, true
			}
		}
	}
	return "", Configuration{}, false
}

func (service *Service) apiKeySessionHook(ctx *engine.Context) (*contract.Response, error) {
	plaintext, config, found := service.apiKeyFromRequest(ctx)
	if !found {
		return nil, nil
	}
	if len(plaintext) < config.DefaultKeyLength {
		return nil, apiError(contract.StatusForbidden, ErrorInvalidAPIKey)
	}
	result := service.Verify(ctx.GoContext(), VerifyInput{Key: plaintext, ConfigID: config.ConfigID})
	if !result.Valid || result.Key == nil {
		code := ErrorInvalidAPIKey
		if result.Error != nil && result.Error.Code != "" {
			code = result.Error.Code
		}
		status := contract.StatusUnauthorized
		if code == ErrorRateLimited || code == ErrorUsageExceeded {
			status = contract.StatusTooManyRequests
		}
		return nil, apiError(status, code)
	}
	if config.References != ReferenceUser {
		return nil, apiError(contract.StatusUnauthorized, ErrorInvalidReferenceID)
	}
	user, err := service.adapter.FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: result.Key.ReferenceID}},
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, apiError(contract.StatusUnauthorized, ErrorInvalidReferenceID)
	}
	now := service.clock().UTC()
	expiresAt := now.Add(7 * 24 * time.Hour)
	if result.Key.ExpiresAt != nil {
		expiresAt = *result.Key.ExpiresAt
	}
	userAgent, _ := ctx.Request().Headers().Get("user-agent")
	session := storage.Record{
		"id": result.Key.ID, "token": plaintext, "userId": result.Key.ReferenceID,
		"userAgent": nullableText(userAgent), "ipAddress": nullableText(ctx.Request().PeerAddress()),
		"createdAt": now, "updatedAt": now, "expiresAt": expiresAt,
	}
	singleauth.SetEndpointSession(ctx, &singleauth.PluginSessionState{Session: session, User: user})
	if ctx.Path() != "/get-session" {
		return nil, nil
	}
	publicUser := any(user)
	if service.options.Runtime.SerializeUser != nil {
		publicUser = service.options.Runtime.SerializeUser(user)
	}
	publicSession := any(session)
	if service.options.Runtime.SerializeSession != nil {
		publicSession = service.options.Runtime.SerializeSession(session)
	}
	response, err := contract.JSONResponse(contract.StatusOK, map[string]any{
		"user": publicUser, "session": publicSession,
	})
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func (service *Service) endpointActor(ctx *engine.Context, required bool) (string, error) {
	return service.endpointActorWithResolver(ctx, required, service.options.Runtime.ResolveSession)
}

func (service *Service) authoritativeEndpointActor(ctx *engine.Context, required bool) (string, error) {
	resolver := service.options.Runtime.ResolveAuthoritativeSession
	if resolver == nil {
		resolver = service.options.Runtime.ResolveSession
	}
	return service.endpointActorWithResolver(ctx, required, resolver)
}

func (service *Service) endpointActorWithResolver(
	ctx *engine.Context,
	required bool,
	resolver ResolveSessionFunc,
) (string, error) {
	if resolver == nil {
		if required {
			return "", apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
		return "", nil
	}
	state, err := resolver(ctx)
	if err != nil {
		if required {
			return "", err
		}
		return "", nil
	}
	if state == nil {
		if required {
			return "", apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
		}
		return "", nil
	}
	userID, _ := recordString(state.User, "id")
	if required && userID == "" {
		return "", apiError(contract.StatusUnauthorized, ErrorUnauthorizedSession)
	}
	return userID, nil
}
