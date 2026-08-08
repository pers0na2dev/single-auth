package oauthprovider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/storage"
)

const (
	MCPAuthorizePath    = "/oauth2/authorize"
	MCPConsentPath      = "/oauth2/consent"
	MCPRegistrationPath = "/oauth2/register"
	MCPTokenPath        = "/oauth2/token"
	mcpConsentCookie    = "oauth_provider_consent"
)

// MCPAuthorizationSession is the authenticated browser session bound to an
// OAuth authorization request.
type MCPAuthorizationSession struct {
	Session storage.Record
	User    storage.Record
}

// MCPAuthorizationRuntime contains the host services used by the dynamic
// registration, authorization, consent, token, and JWKS endpoints.
type MCPAuthorizationRuntime struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	Random            io.Reader
	Secret            string
	ResolveBaseURL    func(contract.Request) (string, error)
	ResolveSession    func(*engine.Context, bool) (*MCPAuthorizationSession, error)
	EncryptSecret     func([]byte) (string, error)
	DecryptSecret     func(string) ([]byte, error)
}

// MCPAuthorizationOptions configures the OAuth 2.1 authorization server used
// by MCP clients. Dynamic public clients always use PKCE S256.
type MCPAuthorizationOptions struct {
	Issuer                                       string
	LoginPage                                    string
	ConsentPage                                  string
	Scopes                                       []string
	ValidAudiences                               []string
	AllowDynamicClientRegistration               bool
	AllowUnauthenticatedPublicClientRegistration bool
	AccessTokenExpiresIn                         time.Duration
	IDTokenExpiresIn                             time.Duration
	RefreshTokenExpiresIn                        time.Duration
	AuthorizationCodeExpiresIn                   time.Duration
	JWT                                          jwtplugin.Options
	Runtime                                      MCPAuthorizationRuntime
}

type mcpAuthorizationGrant struct {
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id"`
	SessionID     string   `json:"session_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	Resource      string   `json:"resource"`
	State         string   `json:"state,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	CodeChallenge string   `json:"code_challenge"`
	AuthTime      int64    `json:"auth_time"`
	NeedsConsent  bool     `json:"needs_consent"`
}

// MCPAuthorizationService is the production OAuth server behind the MCP flow.
type MCPAuthorizationService struct {
	options       MCPAuthorizationOptions
	jwt           jwtplugin.Options
	allowedScopes map[string]struct{}
	audiences     map[string]struct{}
	randomMu      sync.Mutex
}

type mcpAuthorizationLockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *mcpAuthorizationLockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

// MCPAuthorizationFactory binds the OAuth server to a root single-auth
// runtime and embeds the matching JWT/JWKS endpoint.
type MCPAuthorizationFactory struct {
	options MCPAuthorizationOptions
	mu      sync.RWMutex
	service *MCPAuthorizationService
}

var _ singleauth.PluginFactory = (*MCPAuthorizationFactory)(nil)

// NewMCPAuthorizationFactory constructs a root-bound MCP OAuth server.
func NewMCPAuthorizationFactory(options MCPAuthorizationOptions) *MCPAuthorizationFactory {
	options.Runtime = MCPAuthorizationRuntime{}
	return &MCPAuthorizationFactory{options: snapshotMCPAuthorizationOptions(options)}
}

func (*MCPAuthorizationFactory) PluginID() string { return PluginID }

func (*MCPAuthorizationFactory) Schema() (storage.Schema, error) {
	return mcpAuthorizationSchema(), nil
}

func (factory *MCPAuthorizationFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if factory == nil {
		return engine.Plugin{}, errors.New("oauthprovider: MCP authorization factory is nil")
	}
	options := snapshotMCPAuthorizationOptions(factory.options)
	options.Runtime = MCPAuthorizationRuntime{
		Adapter: host.Adapter, AdapterForContext: host.AdapterForContext,
		Clock: host.Clock, Random: host.Random, Secret: host.Secret,
		ResolveBaseURL: host.ResolveBaseURL, EncryptSecret: host.EncryptSecret,
		DecryptSecret: host.DecryptSecret,
		ResolveSession: func(ctx *engine.Context, required bool) (*MCPAuthorizationSession, error) {
			mode := singleauth.PluginSessionOptional
			if required {
				mode = singleauth.PluginSessionRequired
			}
			state, err := host.ResolveSession(ctx, mode)
			if err != nil || state == nil {
				return nil, err
			}
			return &MCPAuthorizationSession{Session: state.Session, User: state.User}, nil
		},
	}
	service, err := NewMCPAuthorizationService(options)
	if err != nil {
		return engine.Plugin{}, err
	}
	factory.mu.Lock()
	if factory.service != nil {
		factory.mu.Unlock()
		return engine.Plugin{}, errors.New("oauthprovider: MCP authorization factory is already bound")
	}
	factory.service = service
	factory.mu.Unlock()
	return service.Descriptor()
}

// Service returns the bound production service after singleauth.New.
func (factory *MCPAuthorizationFactory) Service() (*MCPAuthorizationService, error) {
	if factory == nil {
		return nil, errors.New("oauthprovider: MCP authorization factory is nil")
	}
	factory.mu.RLock()
	service := factory.service
	factory.mu.RUnlock()
	if service == nil {
		return nil, errors.New("oauthprovider: MCP authorization factory is not bound")
	}
	return service, nil
}

// NewMCPAuthorizationService validates a standalone transport-neutral server.
func NewMCPAuthorizationService(input MCPAuthorizationOptions) (*MCPAuthorizationService, error) {
	options := snapshotMCPAuthorizationOptions(input)
	if options.Runtime.Adapter == nil {
		return nil, errors.New("oauthprovider: MCP authorization Runtime.Adapter is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, errors.New("oauthprovider: MCP authorization Runtime.ResolveSession is required")
	}
	if options.Runtime.ResolveBaseURL == nil {
		return nil, errors.New("oauthprovider: MCP authorization Runtime.ResolveBaseURL is required")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	options.Runtime.Random = &mcpAuthorizationLockedReader{r: options.Runtime.Random}
	if options.AccessTokenExpiresIn == 0 {
		options.AccessTokenExpiresIn = time.Hour
	}
	if options.IDTokenExpiresIn == 0 {
		options.IDTokenExpiresIn = 10 * time.Hour
	}
	if options.RefreshTokenExpiresIn == 0 {
		options.RefreshTokenExpiresIn = 30 * 24 * time.Hour
	}
	if options.AuthorizationCodeExpiresIn == 0 {
		options.AuthorizationCodeExpiresIn = 5 * time.Minute
	}
	if options.AccessTokenExpiresIn < 0 || options.IDTokenExpiresIn < 0 ||
		options.RefreshTokenExpiresIn < 0 || options.AuthorizationCodeExpiresIn < 0 {
		return nil, errors.New("oauthprovider: MCP authorization expirations must be positive")
	}
	if len(options.Scopes) == 0 {
		options.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	allowedScopes := make(map[string]struct{}, len(options.Scopes))
	for _, scope := range options.Scopes {
		if strings.TrimSpace(scope) == "" {
			return nil, errors.New("oauthprovider: MCP authorization scope must not be empty")
		}
		allowedScopes[scope] = struct{}{}
	}
	audiences := make(map[string]struct{}, len(options.ValidAudiences))
	for _, audience := range options.ValidAudiences {
		if strings.TrimSpace(audience) != "" {
			audiences[audience] = struct{}{}
		}
	}

	jwtOptions := options.JWT
	jwtOptions.Runtime.Adapter = options.Runtime.Adapter
	jwtOptions.Runtime.AdapterForContext = options.Runtime.AdapterForContext
	jwtOptions.Runtime.Clock = options.Runtime.Clock
	jwtOptions.Runtime.Random = options.Runtime.Random
	jwtOptions.Runtime.Secret = options.Runtime.Secret
	jwtOptions.Runtime.EncryptPrivateKey = func(_ context.Context, value []byte) (string, error) {
		if options.Runtime.EncryptSecret == nil {
			return string(value), nil
		}
		return options.Runtime.EncryptSecret(value)
	}
	jwtOptions.Runtime.DecryptPrivateKey = func(_ context.Context, value string) ([]byte, error) {
		if options.Runtime.DecryptSecret == nil {
			return []byte(value), nil
		}
		return options.Runtime.DecryptSecret(value)
	}
	jwtOptions.Runtime.ResolveBaseURL = func(ctx *engine.Context) (string, error) {
		return options.Runtime.ResolveBaseURL(ctx.Request())
	}
	jwtOptions.Runtime.ResolveSession = func(ctx *engine.Context, required bool) (*jwtplugin.SessionState, error) {
		state, err := options.Runtime.ResolveSession(ctx, required)
		if err != nil || state == nil {
			return nil, err
		}
		return &jwtplugin.SessionState{Session: state.Session, User: state.User}, nil
	}
	if options.Issuer != "" {
		issuer := options.Issuer
		jwtOptions.Token.Issuer = &issuer
	}
	return &MCPAuthorizationService{
		options: options, jwt: jwtOptions,
		allowedScopes: allowedScopes, audiences: audiences,
	}, nil
}

// Descriptor returns the OAuth endpoints plus the matching public JWKS route.
func (service *MCPAuthorizationService) Descriptor() (engine.Plugin, error) {
	if service == nil {
		return engine.Plugin{}, errors.New("oauthprovider: MCP authorization service is nil")
	}
	jwtDescriptor, err := jwtplugin.New(service.jwt)
	if err != nil {
		return engine.Plugin{}, err
	}
	schema := mcpAuthorizationSchema()
	endpoints := []engine.Endpoint{
		{Name: "oauthProviderMCPAuthorize", Path: MCPAuthorizePath, Methods: []string{http.MethodGet}, OperationID: "oauth2Authorize", Handler: service.authorize},
		{Name: "oauthProviderMCPConsent", Path: MCPConsentPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Consent", Handler: service.consent},
		{Name: "oauthProviderMCPRegister", Path: MCPRegistrationPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Register", Handler: service.register},
		{Name: "oauthProviderMCPToken", Path: MCPTokenPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Token", Handler: service.token},
	}
	for _, endpoint := range jwtDescriptor.Endpoints {
		if endpoint.Name == "getJwks" {
			endpoints = append(endpoints, endpoint)
		}
	}
	return engine.Plugin{ID: PluginID, Version: Version, Schema: schema, Endpoints: endpoints}, nil
}

func mcpAuthorizationSchema() storage.Schema {
	schema := OAuthProviderSchema()
	for name, model := range jwtplugin.Schema().Models {
		schema.Models[name] = model
	}
	return schema
}

// AuthorizationServerMetadata returns the RFC 8414 document consumed by MCP
// clients during protected-resource discovery.
func (service *MCPAuthorizationService) AuthorizationServerMetadata(authBaseURL string) map[string]any {
	if service == nil {
		return nil
	}
	jwksPath := ""
	if service.jwt.JWKS.Path != nil {
		jwksPath = *service.jwt.JWKS.Path
	}
	metadata := AuthServerMetadata(authBaseURL, MetadataOptions{
		Issuer: service.options.Issuer, Scopes: service.options.Scopes,
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		JWKSPath:                    jwksPath,
		DynamicClientRegistration:   service.options.AllowDynamicClientRegistration,
		UnauthenticatedPublicClient: service.options.AllowUnauthenticatedPublicClientRegistration,
	})
	delete(metadata, "introspection_endpoint")
	delete(metadata, "introspection_endpoint_auth_methods_supported")
	delete(metadata, "revocation_endpoint")
	delete(metadata, "revocation_endpoint_auth_methods_supported")
	return metadata
}

// ResourceService creates a JWT verifier sharing this server's persisted JWKS.
func (service *MCPAuthorizationService) ResourceService(resource any, requiredScopes []string) (*MCPResourceService, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: MCP authorization service is nil")
	}
	issuer := service.options.Issuer
	return NewMCPResourceService(MCPResourceOptions{
		Resource: resource, AuthorizationServers: []string{issuer},
		ScopesSupported: requiredScopes, Issuer: issuer, Audience: resource,
		JWT: service.jwt,
	})
}

func snapshotMCPAuthorizationOptions(input MCPAuthorizationOptions) MCPAuthorizationOptions {
	result := input
	result.Scopes = append([]string(nil), input.Scopes...)
	result.ValidAudiences = append([]string(nil), input.ValidAudiences...)
	if audience, ok := input.JWT.Token.Audience.([]string); ok {
		result.JWT.Token.Audience = append([]string(nil), audience...)
	}
	return result
}

func (service *MCPAuthorizationService) adapter(ctx context.Context) storage.TransactionAdapter {
	if service.options.Runtime.AdapterForContext != nil {
		if adapter := service.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return service.options.Runtime.Adapter
}

func (service *MCPAuthorizationService) randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	service.randomMu.Lock()
	_, err := io.ReadFull(service.options.Runtime.Random, buffer)
	service.randomMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("oauthprovider: generate OAuth value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func (service *MCPAuthorizationService) register(ctx *engine.Context) (contract.Response, error) {
	if !service.options.AllowDynamicClientRegistration {
		return mcpOAuthError(contract.StatusForbidden, "access_denied", "Client registration is disabled")
	}
	body, err := decodeMCPBody(ctx.Request())
	if err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid registration body")
	}
	session, err := service.options.Runtime.ResolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil && !service.options.AllowUnauthenticatedPublicClientRegistration {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_token", "Authentication required for client registration")
	}
	redirectURIs := mcpBodyStrings(body, "redirect_uris")
	if len(redirectURIs) == 0 {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_redirect_uri", "Redirect URIs are required for authorization_code grant")
	}
	for _, redirectURI := range redirectURIs {
		parsed, parseErr := url.Parse(redirectURI)
		if parseErr != nil || parsed.Scheme == "" || parsed.Host == "" || unsafeMCPURLScheme(parsed.Scheme) {
			return mcpOAuthError(contract.StatusBadRequest, "invalid_redirect_uri", "Invalid redirect URI")
		}
	}
	authMethod := mcpBodyString(body, "token_endpoint_auth_method")
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	if session == nil {
		authMethod = "none"
	}
	if authMethod != "none" && authMethod != "client_secret_basic" && authMethod != "client_secret_post" {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "Invalid token endpoint auth method")
	}
	grantTypes := mcpBodyStrings(body, "grant_types")
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	if session == nil && containsMCPString(grantTypes, "client_credentials") {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "client_credentials grant requires authenticated registration")
	}
	responseTypes := mcpBodyStrings(body, "response_types")
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	if !containsMCPString(responseTypes, "code") {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_client_metadata", "authorization_code requires code response type")
	}
	scopes := strings.Fields(mcpBodyString(body, "scope"))
	if len(scopes) == 0 {
		scopes = append([]string(nil), service.options.Scopes...)
	}
	if err := service.validateScopes(scopes); err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_scope", err.Error())
	}
	clientID, err := service.randomToken(24)
	if err != nil {
		return contract.Response{}, err
	}
	public := authMethod == "none"
	clientSecret := ""
	storedSecret := ""
	if !public {
		clientSecret, err = service.randomToken(32)
		if err != nil {
			return contract.Response{}, err
		}
		storedSecret, err = defaultRevokeStoredToken(ctx.GoContext(), clientSecret, RevokeAccessToken)
		if err != nil {
			return contract.Response{}, err
		}
	}
	now := time.Unix(service.options.Runtime.Clock().Unix(), 0).UTC()
	record := storage.Record{
		"clientId": clientID, "redirectUris": redirectURIs, "disabled": false,
		"tokenEndpointAuthMethod": authMethod, "grantTypes": grantTypes,
		"responseTypes": responseTypes, "public": public, "requirePKCE": true,
		"scopes": scopes, "createdAt": now, "updatedAt": now,
	}
	if storedSecret != "" {
		record["clientSecret"] = storedSecret
		record["type"] = "web"
	}
	if name := mcpBodyString(body, "client_name"); name != "" {
		record["name"] = name
	}
	if session != nil {
		if userID := mcpRecordString(session.User, "id"); userID != "" {
			record["userId"] = userID
		}
	}
	if _, err := service.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{Model: "oauthClient", Data: record}); err != nil {
		return contract.Response{}, err
	}
	response := map[string]any{
		"client_id": clientID, "client_id_issued_at": now.Unix(),
		"redirect_uris": redirectURIs, "token_endpoint_auth_method": authMethod,
		"grant_types": grantTypes, "response_types": responseTypes,
		"scope": strings.Join(scopes, " "), "require_pkce": true,
	}
	if clientSecret != "" {
		response["client_secret"] = clientSecret
		response["client_secret_expires_at"] = 0
	}
	result, err := contract.JSONResponse(http.StatusCreated, response)
	if err != nil {
		return contract.Response{}, err
	}
	return result.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (service *MCPAuthorizationService) authorize(ctx *engine.Context) (contract.Response, error) {
	query, err := ctx.Request().Query()
	if err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid authorization query")
	}
	clientID := query.Get("client_id")
	redirectURI := query.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || query.Get("response_type") != "code" {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "client_id, redirect_uri, and response_type=code are required")
	}
	client, err := service.findClient(ctx.GoContext(), clientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil || !containsMCPString(mcpRecordStrings(client, "redirectUris"), redirectURI) {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_client", "Invalid client or redirect URI")
	}
	if disabled, _ := client["disabled"].(bool); disabled {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "Client is disabled")
	}
	scopes := strings.Fields(query.Get("scope"))
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	if err := service.validateScopes(scopes); err != nil {
		return mcpOAuthRedirectError(redirectURI, query.Get("state"), "invalid_scope", err.Error())
	}
	resource := query.Get("resource")
	if len(service.audiences) > 0 {
		if _, valid := service.audiences[resource]; !valid {
			return mcpOAuthRedirectError(redirectURI, query.Get("state"), "invalid_target", "Invalid resource audience")
		}
	}
	public, _ := client["public"].(bool)
	challenge := query.Get("code_challenge")
	method := query.Get("code_challenge_method")
	if (public || mcpRecordBool(client, "requirePKCE")) && (challenge == "" || !strings.EqualFold(method, "S256")) {
		return mcpOAuthRedirectError(redirectURI, query.Get("state"), "invalid_request", "PKCE S256 is required")
	}
	session, err := service.options.Runtime.ResolveSession(ctx, false)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil || session.User == nil || session.Session == nil {
		login := service.options.LoginPage
		if login == "" {
			return mcpOAuthError(contract.StatusUnauthorized, "login_required", "Authentication is required")
		}
		return mcpRedirect(login + "?" + ctx.Request().RawQuery()), nil
	}
	grant := mcpAuthorizationGrant{
		ClientID: clientID, UserID: mcpRecordString(session.User, "id"),
		SessionID: mcpRecordString(session.Session, "id"), RedirectURI: redirectURI,
		Scopes: scopes, Resource: resource, State: query.Get("state"), Nonce: query.Get("nonce"),
		CodeChallenge: challenge, AuthTime: mcpRecordTimeUnix(session.Session, "createdAt"), NeedsConsent: true,
	}
	consentCode, err := service.storeGrant(ctx.GoContext(), grant)
	if err != nil {
		return contract.Response{}, err
	}
	ctx.AddResponseHeader("Set-Cookie", cookies.Serialize(mcpConsentCookie, consentCode, cookies.Options{
		Path: "/", HTTPOnly: true, SameSite: "lax",
	}))
	consentPage := service.options.ConsentPage
	if consentPage == "" {
		consentPage = MCPConsentPath
	}
	values := url.Values{"consent_code": {consentCode}, "client_id": {clientID}, "scope": {strings.Join(scopes, " ")}}
	return mcpRedirect(consentPage + "?" + values.Encode()), nil
}

func (service *MCPAuthorizationService) consent(ctx *engine.Context) (contract.Response, error) {
	session, err := service.options.Runtime.ResolveSession(ctx, true)
	if err != nil {
		return contract.Response{}, err
	}
	if session == nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_token", "Authentication required")
	}
	body, err := decodeMCPBody(ctx.Request())
	if err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid consent body")
	}
	consentCode := mcpBodyString(body, "consent_code")
	if consentCode == "" {
		cookieHeader, _ := ctx.Request().Headers().Get("Cookie")
		consentCode, _ = cookies.Parse(cookieHeader).Get(mcpConsentCookie)
	}
	if consentCode == "" {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "missing oauth query")
	}
	record, err := service.adapter(ctx.GoContext()).ConsumeOne(ctx.GoContext(), storage.ConsumeOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "mcp-consent:" + consentCode}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	grant, err := service.decodeGrant(record)
	if err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid or expired consent request")
	}
	if grant.UserID != mcpRecordString(session.User, "id") {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_token", "Consent session does not match")
	}
	accepted, _ := body["accept"].(bool)
	if !accepted {
		return contract.JSONResponse(contract.StatusOK, map[string]any{
			"redirect": true, "url": mcpErrorURL(grant.RedirectURI, grant.State, "access_denied", "User denied access"),
		})
	}
	requestedScopes := strings.Fields(mcpBodyString(body, "scope"))
	if len(requestedScopes) > 0 {
		for _, scope := range requestedScopes {
			if !containsMCPString(grant.Scopes, scope) {
				return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "Scope not originally requested")
			}
		}
		grant.Scopes = requestedScopes
	}
	now := time.Unix(service.options.Runtime.Clock().Unix(), 0).UTC()
	found, err := service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthConsent", Where: []storage.Where{{Field: "clientId", Value: grant.ClientID}, {Field: "userId", Value: grant.UserID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if found == nil {
		_, err = service.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{Model: "oauthConsent", Data: storage.Record{
			"clientId": grant.ClientID, "userId": grant.UserID, "scopes": grant.Scopes,
			"createdAt": now, "updatedAt": now,
		}})
	} else {
		_, err = service.adapter(ctx.GoContext()).Update(ctx.GoContext(), storage.UpdateParams{
			Model: "oauthConsent", Where: []storage.Where{{Field: "id", Value: found["id"]}},
			Update: storage.Record{"scopes": grant.Scopes, "updatedAt": now},
		})
	}
	if err != nil {
		return contract.Response{}, err
	}
	grant.NeedsConsent = false
	code, err := service.storeGrant(ctx.GoContext(), grant)
	if err != nil {
		return contract.Response{}, err
	}
	callback, err := url.Parse(grant.RedirectURI)
	if err != nil {
		return contract.Response{}, err
	}
	query := callback.Query()
	query.Set("code", code)
	if grant.State != "" {
		query.Set("state", grant.State)
	}
	if service.options.Issuer != "" {
		query.Set("iss", service.options.Issuer)
	}
	callback.RawQuery = query.Encode()
	return contract.JSONResponse(contract.StatusOK, map[string]any{"redirect": true, "url": callback.String()})
}

func (service *MCPAuthorizationService) token(ctx *engine.Context) (contract.Response, error) {
	body, err := decodeMCPBody(ctx.Request())
	if err != nil {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "Invalid token body")
	}
	grantType := mcpBodyString(body, "grant_type")
	if grantType != "authorization_code" && grantType != "refresh_token" {
		return mcpOAuthError(contract.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
	bodyClientID, bodyClientIDIsString := body["client_id"].(string)
	_, bodyClientIDPresent := body["client_id"]
	if bodyClientIDPresent && !bodyClientIDIsString {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "client_id must be a single string")
	}
	authorization, _ := ctx.Request().Headers().Get("Authorization")
	var basic *ClientCredentials
	if authorization != "" {
		basic, err = BasicToClientCredentials(authorization)
		if err != nil {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "malformed client authentication")
		}
	}
	clientID := bodyClientID
	if basic != nil {
		if bodyClientIDPresent && bodyClientID != basic.ClientID {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "client authentication does not match client_id")
		}
		clientID = basic.ClientID
	}
	if clientID == "" {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "client_id is required")
	}
	client, err := service.findClient(ctx.GoContext(), clientID)
	if err != nil {
		return contract.Response{}, err
	}
	if client == nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "invalid client_id")
	}
	if mcpRecordBool(client, "disabled") {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "Client is disabled")
	}
	public := mcpRecordBool(client, "public")
	authMethod := mcpRecordString(client, "tokenEndpointAuthMethod")
	if authMethod == "" {
		if public {
			authMethod = string(TokenEndpointAuthMethodNone)
		} else {
			authMethod = string(AuthMethodClientSecretBasic)
		}
	}
	bodySecret, bodySecretIsString := body["client_secret"].(string)
	_, bodySecretPresent := body["client_secret"]
	switch AuthMethod(authMethod) {
	case AuthMethodClientSecretBasic:
		if basic == nil || authorization == "" {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "client_secret_basic authentication is required")
		}
		if bodySecretPresent {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "multiple client authentication methods are not allowed")
		}
		valid, verifyErr := defaultRevokeClientSecretVerifier(
			ctx.GoContext(), mcpRecordString(client, "clientSecret"), basic.ClientSecret,
		)
		if verifyErr != nil {
			return contract.Response{}, verifyErr
		}
		if !valid {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "invalid client_secret")
		}
	case AuthMethodClientSecretPost:
		if authorization != "" {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "client_secret_post does not accept Authorization credentials")
		}
		if !bodySecretPresent || !bodySecretIsString || bodySecret == "" {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "client_secret_post authentication is required")
		}
		valid, verifyErr := defaultRevokeClientSecretVerifier(
			ctx.GoContext(), mcpRecordString(client, "clientSecret"), bodySecret,
		)
		if verifyErr != nil {
			return contract.Response{}, verifyErr
		}
		if !valid {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "invalid client_secret")
		}
	case TokenEndpointAuthMethodNone:
		if authorization != "" || bodySecretPresent {
			return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "public clients must not send client credentials")
		}
	default:
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "unsupported client authentication method")
	}
	if grantType == "refresh_token" {
		return service.refreshMCPToken(ctx, body, clientID, client)
	}

	code := mcpBodyString(body, "code")
	redirectURI := mcpBodyString(body, "redirect_uri")
	verifier := mcpBodyString(body, "code_verifier")
	if code == "" || redirectURI == "" {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "authorization code request is incomplete")
	}
	record, err := service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "mcp-code:" + code}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	grant, err := service.decodeGrant(record)
	if err != nil || grant.NeedsConsent {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "invalid code")
	}
	if grant.ClientID != clientID || grant.RedirectURI != redirectURI {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_client", "invalid client or redirect_uri")
	}
	requirePKCE := public || mcpRecordBool(client, "requirePKCE") || grant.CodeChallenge != ""
	if !mcpTokenPKCEValid(grant, verifier, requirePKCE) {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "code verification failed")
	}

	record, err = service.adapter(ctx.GoContext()).ConsumeOne(ctx.GoContext(), storage.ConsumeOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: "mcp-code:" + code}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	grant, err = service.decodeGrant(record)
	if err != nil || grant.NeedsConsent {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "invalid code")
	}
	if grant.ClientID != clientID || grant.RedirectURI != redirectURI ||
		!mcpTokenPKCEValid(grant, verifier, requirePKCE) {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "authorization code no longer matches the request")
	}
	user, err := service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: grant.UserID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if user == nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "user not found")
	}
	now := time.Unix(service.options.Runtime.Clock().Unix(), 0).UTC()
	accessExpiresAt := now.Add(service.options.AccessTokenExpiresIn)
	accessToken, err := jwtplugin.SignJWT(ctx, service.jwt, map[string]any{
		"sub": grant.UserID, "aud": grant.Resource, "azp": clientID,
		"scope": strings.Join(grant.Scopes, " "), "sid": grant.SessionID,
		"iat": now.Unix(), "exp": accessExpiresAt.Unix(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	idToken, err := jwtplugin.SignJWT(ctx, service.jwt, map[string]any{
		"sub": grant.UserID, "aud": clientID, "nonce": grant.Nonce,
		"auth_time": grant.AuthTime, "iat": now.Unix(), "exp": now.Add(service.options.IDTokenExpiresIn).Unix(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	response := map[string]any{
		"access_token": accessToken, "expires_in": int64(service.options.AccessTokenExpiresIn.Seconds()),
		"id_token": idToken, "scope": strings.Join(grant.Scopes, " "), "token_type": "Bearer",
	}
	if containsMCPString(grant.Scopes, "offline_access") {
		refresh, err := service.randomToken(32)
		if err != nil {
			return contract.Response{}, err
		}
		stored, err := defaultRevokeStoredToken(ctx.GoContext(), refresh, RevokeRefreshToken)
		if err != nil {
			return contract.Response{}, err
		}
		data := storage.Record{
			"token": stored, "clientId": clientID, "userId": grant.UserID,
			"sessionId": grant.SessionID, "expiresAt": now.Add(service.options.RefreshTokenExpiresIn),
			"createdAt": now, "scopes": grant.Scopes,
		}
		if grant.AuthTime > 0 {
			data["authTime"] = time.Unix(grant.AuthTime, 0).UTC()
		}
		if grant.Resource != "" {
			data["referenceId"] = grant.Resource
		}
		if _, err := service.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{Model: "oauthRefreshToken", Data: data}); err != nil {
			return contract.Response{}, err
		}
		response["refresh_token"] = refresh
	}
	result, err := contract.JSONResponse(contract.StatusOK, response)
	if err != nil {
		return contract.Response{}, err
	}
	return result.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (service *MCPAuthorizationService) refreshMCPToken(
	ctx *engine.Context,
	body map[string]any,
	clientID string,
	client storage.Record,
) (contract.Response, error) {
	refreshToken, refreshTokenIsString := body["refresh_token"].(string)
	if !refreshTokenIsString || refreshToken == "" {
		return mcpOAuthError(contract.StatusBadRequest, "invalid_request", "refresh_token is required")
	}
	if !revokeClientAllowsGrant(client, "refresh_token") {
		return mcpOAuthError(contract.StatusBadRequest, "unauthorized_client", "client is not authorized to use refresh_token")
	}
	storedToken, err := defaultRevokeStoredToken(ctx.GoContext(), refreshToken, RevokeRefreshToken)
	if err != nil {
		return contract.Response{}, err
	}
	refresh, err := service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "oauthRefreshToken", Where: []storage.Where{{Field: "token", Value: storedToken}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if refresh == nil || mcpRecordString(refresh, "clientId") != clientID {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "invalid refresh token")
	}
	if refresh["revoked"] != nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "invalid refresh token")
	}
	expiresAt, validExpiry := revokeTimeValue(refresh["expiresAt"])
	if !validExpiry || !expiresAt.After(service.options.Runtime.Clock()) {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "refresh token expired")
	}
	grantedScopes := mcpRecordStrings(refresh, "scopes")
	requestedScopes := strings.Fields(mcpBodyString(body, "scope"))
	if len(requestedScopes) == 0 {
		requestedScopes = append([]string(nil), grantedScopes...)
	}
	for _, scope := range requestedScopes {
		if !containsMCPString(grantedScopes, scope) {
			return mcpOAuthError(contract.StatusBadRequest, "invalid_scope", "requested scope exceeds the original grant")
		}
	}
	userID := mcpRecordString(refresh, "userId")
	user, err := service.adapter(ctx.GoContext()).FindOne(ctx.GoContext(), storage.FindOneParams{
		Model: "user", Where: []storage.Where{{Field: "id", Value: userID}},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if user == nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "user not found")
	}
	resource := mcpRecordString(refresh, "referenceId")
	if requestedResource := mcpBodyString(body, "resource"); requestedResource != "" {
		if resource != "" && requestedResource != resource {
			return mcpOAuthError(contract.StatusBadRequest, "invalid_target", "resource does not match the original grant")
		}
		resource = requestedResource
	}
	if len(service.audiences) > 0 {
		if _, valid := service.audiences[resource]; !valid {
			return mcpOAuthError(contract.StatusBadRequest, "invalid_target", "Invalid resource audience")
		}
	}
	now := time.Unix(service.options.Runtime.Clock().Unix(), 0).UTC()
	refreshID := refresh["id"]
	if refreshID == nil {
		return contract.Response{}, errors.New("oauthprovider: stored MCP refresh token has no id")
	}
	consumed, err := service.adapter(ctx.GoContext()).IncrementOne(ctx.GoContext(), storage.IncrementOneParams{
		Model: "oauthRefreshToken",
		Where: []storage.Where{
			{Field: "id", Value: refreshID},
			{Field: "revoked", Operator: storage.OpEq, Value: nil},
		},
		Increment: map[string]float64{}, Set: storage.Record{"revoked": now},
	})
	if err != nil {
		return contract.Response{}, err
	}
	if consumed == nil {
		return mcpOAuthError(contract.StatusUnauthorized, "invalid_grant", "invalid refresh token")
	}

	accessExpiresAt := now.Add(service.options.AccessTokenExpiresIn)
	accessToken, err := jwtplugin.SignJWT(ctx, service.jwt, map[string]any{
		"sub": userID, "aud": resource, "azp": clientID,
		"scope": strings.Join(requestedScopes, " "), "sid": mcpRecordString(refresh, "sessionId"),
		"iat": now.Unix(), "exp": accessExpiresAt.Unix(),
	})
	if err != nil {
		return contract.Response{}, err
	}
	response := map[string]any{
		"access_token": accessToken, "expires_in": int64(service.options.AccessTokenExpiresIn.Seconds()),
		"scope": strings.Join(requestedScopes, " "), "token_type": "Bearer",
	}
	if containsMCPString(requestedScopes, "openid") {
		authTime := mcpRecordTimeUnix(refresh, "authTime")
		idToken, signErr := jwtplugin.SignJWT(ctx, service.jwt, map[string]any{
			"sub": userID, "aud": clientID, "auth_time": authTime,
			"iat": now.Unix(), "exp": now.Add(service.options.IDTokenExpiresIn).Unix(),
		})
		if signErr != nil {
			return contract.Response{}, signErr
		}
		response["id_token"] = idToken
	}
	if containsMCPString(requestedScopes, "offline_access") {
		rotated, randomErr := service.randomToken(32)
		if randomErr != nil {
			return contract.Response{}, randomErr
		}
		storedRotated, storeErr := defaultRevokeStoredToken(ctx.GoContext(), rotated, RevokeRefreshToken)
		if storeErr != nil {
			return contract.Response{}, storeErr
		}
		data := storage.Record{
			"token": storedRotated, "clientId": clientID, "userId": userID,
			"expiresAt": now.Add(service.options.RefreshTokenExpiresIn), "createdAt": now,
			"scopes": requestedScopes,
		}
		if sessionID := mcpRecordString(refresh, "sessionId"); sessionID != "" {
			data["sessionId"] = sessionID
		}
		if authTime, ok := revokeTimeValue(refresh["authTime"]); ok {
			data["authTime"] = authTime
		}
		if resource != "" {
			data["referenceId"] = resource
		}
		if _, createErr := service.adapter(ctx.GoContext()).Create(ctx.GoContext(), storage.CreateParams{
			Model: "oauthRefreshToken", Data: data,
		}); createErr != nil {
			return contract.Response{}, createErr
		}
		response["refresh_token"] = rotated
	}
	result, err := contract.JSONResponse(contract.StatusOK, response)
	if err != nil {
		return contract.Response{}, err
	}
	return result.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache"), nil
}

func (service *MCPAuthorizationService) storeGrant(ctx context.Context, grant mcpAuthorizationGrant) (string, error) {
	code, err := service.randomToken(32)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	prefix := "mcp-code:"
	if grant.NeedsConsent {
		prefix = "mcp-consent:"
	}
	_, err = service.adapter(ctx).Create(ctx, storage.CreateParams{Model: "verification", Data: storage.Record{
		"identifier": prefix + code, "value": string(encoded),
		"expiresAt": service.options.Runtime.Clock().Add(service.options.AuthorizationCodeExpiresIn),
	}})
	if err != nil {
		return "", err
	}
	return code, nil
}

func (service *MCPAuthorizationService) decodeGrant(record storage.Record) (mcpAuthorizationGrant, error) {
	if record == nil {
		return mcpAuthorizationGrant{}, errors.New("missing grant")
	}
	expiresAt, ok := record["expiresAt"].(time.Time)
	if !ok || expiresAt.Before(service.options.Runtime.Clock()) {
		return mcpAuthorizationGrant{}, errors.New("expired grant")
	}
	encoded, _ := record["value"].(string)
	var grant mcpAuthorizationGrant
	if err := json.Unmarshal([]byte(encoded), &grant); err != nil {
		return mcpAuthorizationGrant{}, err
	}
	return grant, nil
}

func (service *MCPAuthorizationService) findClient(ctx context.Context, clientID string) (storage.Record, error) {
	return service.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}},
	})
}

func (service *MCPAuthorizationService) validateScopes(scopes []string) error {
	for _, scope := range scopes {
		if _, ok := service.allowedScopes[scope]; !ok {
			return fmt.Errorf("cannot request scope %s", scope)
		}
	}
	return nil
}

func decodeMCPBody(request contract.Request) (map[string]any, error) {
	body := request.Body()
	contentType, _ := request.Headers().Get("Content-Type")
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") || strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		result := map[string]any{}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil, err
		}
		return result, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	result := make(map[string]any, len(values))
	for key, entries := range values {
		if len(entries) == 1 {
			result[key] = entries[0]
		} else {
			result[key] = append([]string(nil), entries...)
		}
	}
	return result, nil
}

func mcpBodyString(body map[string]any, key string) string {
	value, _ := body[key].(string)
	return value
}

func mcpBodyStrings(body map[string]any, key string) []string {
	switch value := body[key].(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		result := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case string:
		return []string{value}
	default:
		return nil
	}
}

func mcpRecordString(record storage.Record, key string) string {
	value, _ := record[key].(string)
	return value
}

func mcpRecordStrings(record storage.Record, key string) []string {
	return mcpBodyStrings(map[string]any{key: record[key]}, key)
}

func mcpRecordBool(record storage.Record, key string) bool {
	value, _ := record[key].(bool)
	return value
}

func mcpRecordTimeUnix(record storage.Record, key string) int64 {
	switch value := record[key].(type) {
	case time.Time:
		return value.Unix()
	case *time.Time:
		if value != nil {
			return value.Unix()
		}
	}
	return 0
}

func containsMCPString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func unsafeMCPURLScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "javascript", "data", "vbscript":
		return true
	default:
		return false
	}
}

func mcpPKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func mcpTokenPKCEValid(grant mcpAuthorizationGrant, verifier string, required bool) bool {
	if !required && grant.CodeChallenge == "" {
		return true
	}
	return verifier != "" && grant.CodeChallenge != "" &&
		mcpPKCEChallenge(verifier) == grant.CodeChallenge
}

func mcpOAuthError(status int, code, description string) (contract.Response, error) {
	response, err := contract.JSONResponse(status, map[string]any{"error": code, "error_description": description})
	return response, err
}

func mcpErrorURL(destination, state, code, description string) string {
	parsed, err := url.Parse(destination)
	if err != nil {
		return destination
	}
	query := parsed.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func mcpOAuthRedirectError(destination, state, code, description string) (contract.Response, error) {
	return mcpRedirect(mcpErrorURL(destination, state, code, description)), nil
}

func mcpRedirect(destination string) contract.Response {
	return contract.NewResponse(contract.StatusFound, contract.NewHeaders(
		contract.HeaderField{Name: "Location", Value: destination},
	), nil)
}
