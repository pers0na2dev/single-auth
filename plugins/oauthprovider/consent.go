package oauthprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	GetConsentPath    = "/oauth2/get-consent"
	GetConsentsPath   = "/oauth2/get-consents"
	UpdateConsentPath = "/oauth2/update-consent"
	DeleteConsentPath = "/oauth2/delete-consent"
)

var defaultConsentScopes = []string{"openid", "profile", "email", "offline_access"}

// ConsentSession is the authenticated session/user pair required by the
// consent-management endpoints.
type ConsentSession struct {
	Session storage.Record
	User    storage.Record
}

// ConsentSessionResolver resolves the same required session used by Better
// Auth's sessionMiddleware. Implementations must be safe for concurrent use.
type ConsentSessionResolver func(*engine.Context) (*ConsentSession, error)

// ConsentRuntime contains dependencies injected by NewConsentFactory. It is
// public so a transport-neutral plugin can also be assembled independently.
type ConsentRuntime struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	ResolveSession    ConsentSessionResolver
}

// ConsentOptions configures OAuth consent persistence and the global fallback
// scope set. A client's own scopes take precedence when they are present.
type ConsentOptions struct {
	Scopes  []string
	Runtime ConsentRuntime
}

// CreateConsentInput is the server-side input used to persist a grant. It is
// intentionally not exposed as an HTTP endpoint: upstream creates grants from
// trusted server flows and only exposes management endpoints to the browser.
type CreateConsentInput struct {
	ClientID    string
	Scopes      []string
	UserID      string
	ReferenceID string
}

// UpdateConsentInput is the only mutation accepted by the public update
// endpoint in single-auth 1.6.26.
type UpdateConsentInput struct {
	ID     string
	UserID string
	Scopes []string
}

// ConsentService owns the production persistence operations shared by HTTP
// endpoints and trusted server-side callers.
type ConsentService struct {
	options ConsentOptions
}

// NewConsentService validates and snapshots a production consent service.
func NewConsentService(input ConsentOptions) (*ConsentService, error) {
	options := snapshotConsentOptions(input)
	if options.Runtime.Adapter == nil {
		return nil, errors.New("oauthprovider: ConsentRuntime.Adapter is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, errors.New("oauthprovider: ConsentRuntime.ResolveSession is required")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Scopes == nil {
		options.Scopes = append([]string(nil), defaultConsentScopes...)
	}
	return &ConsentService{options: options}, nil
}

// NewConsentPlugin constructs the four transport-neutral consent management
// endpoints. The descriptor runs unchanged through net/http, fasthttp, Fiber,
// and direct API dispatch.
func NewConsentPlugin(options ConsentOptions) (engine.Plugin, error) {
	service, err := NewConsentService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	return service.Descriptor(), nil
}

// ConsentFactory delays runtime binding until single-auth has created the
// final adapter and core session implementation.
type ConsentFactory struct {
	options ConsentOptions
	mu      sync.RWMutex
	service *ConsentService
}

// NewConsentFactory binds consent endpoints to the root single-auth runtime.
// The returned factory also exposes the trusted CreateConsent method after it
// has been bound by singleauth.New.
func NewConsentFactory(options ConsentOptions) *ConsentFactory {
	options.Runtime = ConsentRuntime{}
	return &ConsentFactory{options: snapshotConsentOptions(options)}
}

func (*ConsentFactory) PluginID() string { return PluginID }

func (*ConsentFactory) Schema() (storage.Schema, error) {
	return OAuthProviderSchema(), nil
}

func (factory *ConsentFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if factory == nil {
		return engine.Plugin{}, errors.New("oauthprovider: consent factory is nil")
	}
	options := snapshotConsentOptions(factory.options)
	options.Runtime = ConsentRuntime{
		Adapter:           host.Adapter,
		AdapterForContext: host.AdapterForContext,
		Clock:             host.Clock,
		ResolveSession: func(ctx *engine.Context) (*ConsentSession, error) {
			state, err := host.ResolveSession(ctx, singleauth.PluginSessionRequired)
			if err != nil || state == nil {
				return nil, err
			}
			return &ConsentSession{Session: state.Session, User: state.User}, nil
		},
	}
	service, err := NewConsentService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	factory.mu.Lock()
	if factory.service != nil {
		factory.mu.Unlock()
		return engine.Plugin{}, errors.New("oauthprovider: consent factory is already bound")
	}
	factory.service = service
	factory.mu.Unlock()
	return service.Descriptor(), nil
}

// CreateConsent persists a trusted server-side consent using the runtime bound
// by singleauth.New.
func (factory *ConsentFactory) CreateConsent(
	ctx context.Context,
	input CreateConsentInput,
) (storage.Record, error) {
	if factory == nil {
		return nil, errors.New("oauthprovider: consent factory is nil")
	}
	factory.mu.RLock()
	service := factory.service
	factory.mu.RUnlock()
	if service == nil {
		return nil, errors.New("oauthprovider: consent factory is not bound to single-auth")
	}
	return service.CreateConsent(ctx, input)
}

// Descriptor returns an isolated OAuth-provider descriptor containing the
// consent-management surface.
func (service *ConsentService) Descriptor() engine.Plugin {
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: OAuthProviderSchema(),
		Endpoints: []engine.Endpoint{
			{
				Name: "getOAuthConsent", Path: GetConsentPath,
				Methods: []string{http.MethodGet}, OperationID: "getOAuthConsent",
				Handler: service.getConsentEndpoint,
				Metadata: map[string]any{"openapi": map[string]any{
					"description": "Gets details of a specific OAuth2 consent for a user",
				}},
			},
			{
				Name: "getOAuthConsents", Path: GetConsentsPath,
				Methods: []string{http.MethodGet}, OperationID: "getOAuthConsents",
				Handler: service.getConsentsEndpoint,
				Metadata: map[string]any{"openapi": map[string]any{
					"description": "Gets all available OAuth2 consents for a user",
				}},
			},
			{
				Name: "updateOAuthConsent", Path: UpdateConsentPath,
				Methods: []string{http.MethodPost}, OperationID: "updateOAuthConsent",
				Handler: service.updateConsentEndpoint,
				Metadata: map[string]any{"openapi": map[string]any{
					"description": "Updates consent granted to a client.",
				}},
			},
			{
				Name: "deleteOAuthConsent", Path: DeleteConsentPath,
				Methods: []string{http.MethodPost}, OperationID: "deleteOAuthConsent",
				Handler: service.deleteConsentEndpoint,
				Metadata: map[string]any{"openapi": map[string]any{
					"description": "Deletes consent granted to a client",
				}},
			},
		},
	}
}

func snapshotConsentOptions(input ConsentOptions) ConsentOptions {
	result := input
	result.Scopes = cloneConsentScopes(input.Scopes)
	return result
}

func (service *ConsentService) adapter(ctx context.Context) storage.TransactionAdapter {
	if service.options.Runtime.AdapterForContext != nil {
		if adapter := service.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return service.options.Runtime.Adapter
}

// CreateConsent persists a grant with the same second-precision timestamps as
// single-auth's OAuth provider.
func (service *ConsentService) CreateConsent(
	ctx context.Context,
	input CreateConsentInput,
) (storage.Record, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: consent service is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := service.options.Runtime.Clock()
	now = time.Unix(now.Unix(), 0).UTC()
	data := storage.Record{
		"clientId":  input.ClientID,
		"scopes":    cloneConsentScopes(input.Scopes),
		"createdAt": now,
		"updatedAt": now,
	}
	if input.UserID != "" {
		data["userId"] = input.UserID
	}
	if input.ReferenceID != "" {
		data["referenceId"] = input.ReferenceID
	}
	created, err := service.adapter(ctx).Create(ctx, storage.CreateParams{
		Model: "oauthConsent", Data: data,
	})
	if err != nil {
		return nil, fmt.Errorf("oauthprovider: create consent: %w", err)
	}
	return created, nil
}

// GetConsent returns a consent only to its owning user.
func (service *ConsentService) GetConsent(
	ctx context.Context,
	userID, id string,
) (storage.Record, error) {
	ctx = normalizedConsentContext(ctx)
	if userID == "" {
		return nil, consentUnauthorized()
	}
	if id == "" {
		return nil, consentNotFound("missing id parameter")
	}
	consent, err := service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthConsent", Where: []storage.Where{{Field: "id", Value: id}},
	})
	if err != nil {
		return nil, err
	}
	if consent == nil {
		return nil, consentNotFound("no consent")
	}
	if consentRecordString(consent, "userId") != userID {
		return nil, consentUnauthorized()
	}
	return consent, nil
}

// ListConsents preserves adapter insertion order, matching findMany upstream.
func (service *ConsentService) ListConsents(
	ctx context.Context,
	userID string,
) ([]storage.Record, error) {
	ctx = normalizedConsentContext(ctx)
	if userID == "" {
		return nil, consentUnauthorized()
	}
	return service.adapter(ctx).FindMany(ctx, storage.FindManyParams{
		Model: "oauthConsent",
		Where: []storage.Where{{Field: "userId", Value: userID}},
	})
}

// UpdateConsent checks the client-specific scope set before mutating a grant.
func (service *ConsentService) UpdateConsent(
	ctx context.Context,
	input UpdateConsentInput,
) (storage.Record, error) {
	ctx = normalizedConsentContext(ctx)
	consent, err := service.GetConsent(ctx, input.UserID, input.ID)
	if err != nil {
		return nil, err
	}
	clientID := consentRecordString(consent, "clientId")
	client, err := service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, consentNotFound("client not found")
	}
	allowedScopes, present := consentRecordStrings(client, "scopes")
	if !present {
		allowedScopes = cloneConsentScopes(service.options.Scopes)
	}
	for _, scope := range input.Scopes {
		if !containsConsentScope(allowedScopes, scope) {
			owner := consentClientOwner(client)
			return nil, consentProtocolError(
				contract.StatusBadRequest,
				"invalid_request",
				fmt.Sprintf("unable to provide scopes to %s", owner),
			)
		}
	}
	now := service.options.Runtime.Clock()
	now = time.Unix(now.Unix(), 0).UTC()
	updated, err := service.adapter(ctx).Update(ctx, storage.UpdateParams{
		Model: "oauthConsent",
		Where: []storage.Where{{Field: "id", Value: input.ID}},
		Update: storage.Record{
			"scopes":    cloneConsentScopes(input.Scopes),
			"updatedAt": now,
		},
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// DeleteConsent removes a consent only when it belongs to the supplied user.
func (service *ConsentService) DeleteConsent(
	ctx context.Context,
	userID, id string,
) error {
	ctx = normalizedConsentContext(ctx)
	if _, err := service.GetConsent(ctx, userID, id); err != nil {
		return err
	}
	return service.adapter(ctx).Delete(ctx, storage.DeleteParams{
		Model: "oauthConsent", Where: []storage.Where{{Field: "id", Value: id}},
	})
}

func (service *ConsentService) getConsentEndpoint(ctx *engine.Context) (contract.Response, error) {
	userID, err := service.requiredUserID(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	query, err := ctx.Request().Query()
	if err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid query parameters",
		).WithCause(err)
	}
	consent, err := service.GetConsent(ctx.GoContext(), userID, query.Get("id"))
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, consent)
}

func (service *ConsentService) getConsentsEndpoint(ctx *engine.Context) (contract.Response, error) {
	userID, err := service.requiredUserID(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	consents, err := service.ListConsents(ctx.GoContext(), userID)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, consents)
}

func (service *ConsentService) updateConsentEndpoint(ctx *engine.Context) (contract.Response, error) {
	userID, err := service.requiredUserID(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	var body struct {
		ID     string `json:"id"`
		Update struct {
			Scopes *[]string `json:"scopes"`
		} `json:"update"`
	}
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	if body.Update.Scopes == nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		)
	}
	updated, err := service.UpdateConsent(ctx.GoContext(), UpdateConsentInput{
		ID: body.ID, UserID: userID, Scopes: *body.Update.Scopes,
	})
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, updated)
}

func (service *ConsentService) deleteConsentEndpoint(ctx *engine.Context) (contract.Response, error) {
	userID, err := service.requiredUserID(ctx)
	if err != nil {
		return contract.Response{}, err
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(ctx.Request().Body(), &body); err != nil {
		return contract.Response{}, contract.NewAPIError(
			contract.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body",
		).WithCause(err)
	}
	if err := service.DeleteConsent(ctx.GoContext(), userID, body.ID); err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, nil)
}

func (service *ConsentService) requiredUserID(ctx *engine.Context) (string, error) {
	session, err := service.options.Runtime.ResolveSession(ctx)
	if err != nil {
		return "", err
	}
	if session == nil || session.User == nil {
		return "", consentUnauthorized()
	}
	userID := consentRecordString(session.User, "id")
	if userID == "" {
		return "", consentUnauthorized()
	}
	return userID, nil
}

func consentRecordString(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return value
}

func consentRecordStrings(record storage.Record, key string) ([]string, bool) {
	value, exists := record[key]
	if !exists || value == nil {
		return nil, false
	}
	switch typed := value.(type) {
	case []string:
		return cloneConsentScopes(typed), true
	case []any:
		result := make([]string, 0, len(typed))
		for _, entry := range typed {
			text, ok := entry.(string)
			if !ok {
				return nil, true
			}
			result = append(result, text)
		}
		return result, true
	case string:
		return strings.Fields(typed), true
	default:
		return nil, true
	}
}

func cloneConsentScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	return append(make([]string, 0, len(scopes)), scopes...)
}

func consentClientOwner(client storage.Record) string {
	if value, exists := client["referenceId"]; exists && value != nil {
		if text, ok := value.(string); ok {
			return text
		}
		return fmt.Sprint(value)
	}
	if value, exists := client["userId"]; exists && value != nil {
		if text, ok := value.(string); ok {
			return text
		}
		return fmt.Sprint(value)
	}
	return "undefined"
}

func containsConsentScope(scopes []string, candidate string) bool {
	for _, scope := range scopes {
		if scope == candidate {
			return true
		}
	}
	return false
}

func normalizedConsentContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func consentUnauthorized() *contract.APIError {
	return contract.NewAPIError(contract.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
}

func consentNotFound(description string) *contract.APIError {
	return consentProtocolError(contract.StatusNotFound, "not_found", description)
}

func consentProtocolError(status int, code, description string) *contract.APIError {
	return contract.NewAPIError(status, strings.ToUpper(code), description).WithWireBody(map[string]any{
		"error": code, "error_description": description,
	})
}
