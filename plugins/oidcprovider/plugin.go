package oidcprovider

import (
	"context"
	"crypto/rand"
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
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

type lockedReader struct {
	mu sync.Mutex
	r  io.Reader
}

func (reader *lockedReader) Read(target []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.r.Read(target)
}

type plugin struct {
	options Options
	schema  storage.Schema
	clock   func() time.Time
	random  io.Reader
}

// NormalizeOptions applies the frozen defaults and snapshots mutable option
// values without requiring runtime dependencies.
func NormalizeOptions(input Options) (Options, error) {
	options := input
	options.Schema = input.Schema.Clone()
	options.Scopes = append(
		[]string{"openid", "profile", "email", "offline_access"},
		input.Scopes...,
	)
	options.Metadata = cloneMap(input.Metadata)
	options.TrustedClients = make([]Client, len(input.TrustedClients))
	for index, client := range input.TrustedClients {
		options.TrustedClients[index] = cloneClient(client)
	}
	if options.CodeExpiresIn == 0 {
		options.CodeExpiresIn = defaultCodeExpiresIn
	}
	if options.AccessTokenExpiresIn == 0 {
		options.AccessTokenExpiresIn = defaultAccessTokenExpiresIn
	}
	if options.RefreshTokenExpiresIn == 0 {
		options.RefreshTokenExpiresIn = defaultRefreshTokenExpiresIn
	}
	if options.CodeExpiresIn < 0 || options.AccessTokenExpiresIn < 0 || options.RefreshTokenExpiresIn < 0 {
		return Options{}, errors.New("oidcprovider: token and code lifetimes must be positive")
	}
	if options.DefaultScope == "" {
		options.DefaultScope = "openid"
	}
	if options.StoreClientSecret == "" {
		options.StoreClientSecret = ClientSecretPlain
	}
	switch options.StoreClientSecret {
	case ClientSecretPlain, ClientSecretHashed, ClientSecretEncrypted:
	case ClientSecretCustomHash:
		if options.HashClientSecret == nil {
			return Options{}, errors.New("oidcprovider: HashClientSecret is required for custom-hash storage")
		}
	case ClientSecretCustomEncryption:
		if options.EncryptClientSecret == nil || options.DecryptClientSecret == nil {
			return Options{}, errors.New("oidcprovider: EncryptClientSecret and DecryptClientSecret are required for custom-encryption storage")
		}
	default:
		return Options{}, fmt.Errorf("oidcprovider: unsupported StoreClientSecret mode %q", options.StoreClientSecret)
	}
	return options, nil
}

// New constructs a transport-neutral plugin descriptor.
func New(input Options) (engine.Plugin, error) {
	implementation, err := normalize(input)
	if err != nil {
		return engine.Plugin{}, err
	}
	return implementation.descriptor(), nil
}

// MustNew constructs a descriptor or panics.
func MustNew(options Options) engine.Plugin {
	descriptor, err := New(options)
	if err != nil {
		panic(err)
	}
	return descriptor
}

// NewFactory binds OIDC to root storage, sessions, cookies, verification
// storage, secret rotation, trusted-origin checks, and the optional JWT plugin.
func NewFactory(options Options) singleauth.PluginFactory {
	return &rootFactory{options: options}
}

type rootFactory struct{ options Options }

func (*rootFactory) PluginID() string { return PluginID }

func (factory *rootFactory) Schema() (storage.Schema, error) {
	return resolveSchema(factory.options.Schema)
}

func (factory *rootFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	options := factory.options
	options.Runtime.Adapter = host.Adapter
	options.Runtime.AdapterForContext = host.AdapterForContext
	options.Runtime.Clock = host.Clock
	options.Runtime.Random = host.Random
	options.Runtime.Secret = host.Secret
	options.Runtime.Issuer = host.Options.BaseURL
	options.Runtime.BasePath = host.Options.BasePath
	options.Runtime.ResolveBaseURL = host.ResolveBaseURL
	options.Runtime.SessionCookie = host.SessionCookie
	options.Runtime.CreateVerification = host.CreateVerification
	options.Runtime.FindVerification = host.FindVerification
	options.Runtime.PeekVerification = host.PeekVerification
	options.Runtime.ConsumeVerification = host.ConsumeVerification
	options.Runtime.UpdateVerification = host.UpdateVerification
	options.Runtime.DeleteVerification = host.DeleteVerification
	options.Runtime.EncryptSecret = host.EncryptSecret
	options.Runtime.DecryptSecret = host.DecryptSecret
	options.Runtime.DeleteSession = host.DeleteSession
	options.Runtime.IsTrustedOrigin = host.IsTrustedOrigin
	options.Runtime.ResolveSession = func(ctx *engine.Context, required bool) (*SessionState, error) {
		mode := singleauth.PluginSessionOptional
		if required {
			mode = singleauth.PluginSessionRequired
		}
		state, err := host.ResolveSession(ctx, mode)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.FindSession = func(ctx context.Context, token string) (*SessionState, error) {
		state, err := host.FindSession(ctx, token)
		if err != nil || state == nil {
			return nil, err
		}
		return &SessionState{Session: state.Session, User: state.User}, nil
	}
	options.Runtime.NewSession = func(ctx *engine.Context) *SessionState {
		state := host.NewSession(ctx)
		if state == nil {
			return nil
		}
		return &SessionState{Session: state.Session, User: state.User}
	}
	options.Runtime.SignWithJWTPlugin = func(
		ctx *engine.Context,
		payload map[string]any,
		audience, issuer string,
		expiresAt int64,
	) (string, error) {
		endpoint, ok := findEndpoint(host.ListEndpoints(), "signJWT")
		if !ok {
			return "", errors.New("OIDC: `useJWTPlugin` is enabled but the JWT plugin is not available")
		}
		body, err := json.Marshal(map[string]any{
			"payload": payload,
			"overrideOptions": map[string]any{"jwt": map[string]any{
				"issuer": issuer, "audience": audience, "expirationTime": expiresAt,
			}},
		})
		if err != nil {
			return "", err
		}
		request := ctx.Request().WithMethod(http.MethodPost).WithTarget("/", "").WithBody(body).
			WithHeader("Content-Type", "application/json")
		response, runErr := engine.RunEndpointIsolated(ctx, request, endpoint)
		if runErr != nil {
			return "", runErr
		}
		var result struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(response.Body(), &result); err != nil || result.Token == "" {
			if err == nil {
				err = errors.New("JWT plugin returned an empty token")
			}
			return "", err
		}
		return result.Token, nil
	}
	options.Runtime.VerifyWithJWTPlugin = func(
		ctx *engine.Context,
		token, issuer string,
	) (map[string]any, error) {
		endpoint, ok := findEndpoint(host.ListEndpoints(), "verifyJWT")
		if !ok {
			return nil, errors.New("OIDC: JWT plugin is not available")
		}
		body, err := json.Marshal(map[string]any{"token": token, "issuer": issuer})
		if err != nil {
			return nil, err
		}
		request := ctx.Request().WithMethod(http.MethodPost).WithTarget("/", "").WithBody(body).
			WithHeader("Content-Type", "application/json")
		response, runErr := engine.RunEndpointIsolated(ctx, request, endpoint)
		if runErr != nil {
			return nil, runErr
		}
		var result struct {
			Payload map[string]any `json:"payload"`
		}
		if err := json.Unmarshal(response.Body(), &result); err != nil {
			return nil, err
		}
		return result.Payload, nil
	}
	return New(options)
}

func findEndpoint(endpoints []engine.Endpoint, name string) (engine.Endpoint, bool) {
	for _, endpoint := range endpoints {
		if endpoint.Name == name {
			return endpoint, true
		}
	}
	return engine.Endpoint{}, false
}

func normalize(input Options) (*plugin, error) {
	options, err := NormalizeOptions(input)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(options.LoginPage) == "" {
		return nil, errors.New("oidcprovider: LoginPage is required")
	}
	if options.Runtime.Adapter == nil {
		return nil, errors.New("oidcprovider: Runtime.Adapter is required")
	}
	if options.Runtime.ResolveSession == nil {
		return nil, errors.New("oidcprovider: Runtime.ResolveSession is required")
	}
	if options.Runtime.Secret == "" {
		return nil, errors.New("oidcprovider: Runtime.Secret is required")
	}
	if options.Runtime.ResolveBaseURL == nil {
		issuer := strings.TrimSuffix(options.Runtime.Issuer, "/")
		basePath := options.Runtime.BasePath
		if basePath == "" {
			basePath = "/api/auth"
		}
		if issuer == "" {
			return nil, errors.New("oidcprovider: Runtime.ResolveBaseURL or Runtime.Issuer is required")
		}
		options.Runtime.ResolveBaseURL = func(contract.Request) (string, error) {
			return issuer + basePath, nil
		}
	}
	if options.StoreClientSecret == ClientSecretEncrypted &&
		(options.Runtime.EncryptSecret == nil || options.Runtime.DecryptSecret == nil) {
		return nil, errors.New("oidcprovider: encrypted client-secret storage requires Runtime.EncryptSecret and Runtime.DecryptSecret")
	}
	if options.Runtime.Clock == nil {
		options.Runtime.Clock = time.Now
	}
	if options.Runtime.Random == nil {
		options.Runtime.Random = rand.Reader
	}
	if options.Runtime.AdapterForContext == nil {
		options.Runtime.AdapterForContext = func(context.Context) storage.TransactionAdapter {
			return options.Runtime.Adapter
		}
	}
	schema, err := resolveSchema(options.Schema)
	if err != nil {
		return nil, fmt.Errorf("oidcprovider: schema: %w", err)
	}
	return &plugin{
		options: options, schema: schema, clock: options.Runtime.Clock,
		random: &lockedReader{r: options.Runtime.Random},
	}, nil
}

func (p *plugin) descriptor() engine.Plugin {
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: p.schema.Clone(),
		Endpoints: []engine.Endpoint{
			{Name: "getOpenIdConfig", Path: DiscoveryPath, Methods: []string{http.MethodGet}, OperationID: "getOpenIdConfig", Handler: p.discovery},
			{Name: "oAuth2authorize", Path: AuthorizePath, Methods: []string{http.MethodGet}, OperationID: "oauth2Authorize", Handler: p.authorize},
			{Name: "oAuthConsent", Path: ConsentPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Consent", Handler: p.consent},
			{Name: "oAuth2token", Path: TokenPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Token", Handler: p.token},
			{Name: "oAuth2userInfo", Path: UserInfoPath, Methods: []string{http.MethodGet}, OperationID: "oauth2Userinfo", Handler: p.userInfo},
			{Name: "registerOAuthApplication", Path: RegistrationPath, Methods: []string{http.MethodPost}, Handler: p.register},
			{Name: "getOAuthClient", Path: ClientPath, Methods: []string{http.MethodGet}, Handler: p.getOAuthClient},
			{Name: "endSession", Path: EndSessionPath, Methods: []string{http.MethodGet, http.MethodPost}, Handler: p.endSession},
		},
		Hooks: engine.Hooks{After: []engine.AfterHook{{
			Name:    "oidc-provider-continue-login-prompt",
			Matcher: func(*engine.Context) (bool, error) { return true, nil },
			Handler: p.afterLogin,
		}}},
	}
}

func (p *plugin) adapter(ctx context.Context) storage.TransactionAdapter {
	if p.options.Runtime.AdapterForContext != nil {
		if adapter := p.options.Runtime.AdapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return p.options.Runtime.Adapter
}

func (p *plugin) allScopes() []string {
	return append([]string(nil), p.options.Scopes...)
}

func (p *plugin) randomString(length int, alphabets ...string) (string, error) {
	alphabet := strings.Join(alphabets, "")
	if length < 0 || len(alphabet) < 2 || len(alphabet) > 256 {
		return "", errors.New("oidcprovider: invalid random string parameters")
	}
	limit := 256 - 256%len(alphabet)
	result := make([]byte, 0, length)
	buffer := make([]byte, 1)
	for len(result) < length {
		if _, err := io.ReadFull(p.random, buffer); err != nil {
			return "", err
		}
		if int(buffer[0]) >= limit {
			continue
		}
		result = append(result, alphabet[int(buffer[0])%len(alphabet)])
	}
	return string(result), nil
}

func (p *plugin) resolveIssuer(baseURL string) string {
	if issuer, ok := p.options.Metadata["issuer"].(string); ok && issuer != "" {
		return issuer
	}
	if parsed, err := url.Parse(baseURL); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host
	}
	return strings.TrimSuffix(p.options.Runtime.Issuer, "/")
}

func (p *plugin) createVerification(ctx context.Context, identifier, value string, expiresAt time.Time) (storage.Record, error) {
	if p.options.Runtime.CreateVerification != nil {
		return p.options.Runtime.CreateVerification(ctx, identifier, value, expiresAt)
	}
	now := p.clock().UTC()
	return p.adapter(ctx).Create(ctx, storage.CreateParams{Model: "verification", Data: storage.Record{
		"identifier": identifier, "value": value, "expiresAt": expiresAt,
		"createdAt": now, "updatedAt": now,
	}})
}

func (p *plugin) peekVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if p.options.Runtime.PeekVerification != nil {
		return p.options.Runtime.PeekVerification(ctx, identifier)
	}
	if p.options.Runtime.FindVerification != nil {
		return p.options.Runtime.FindVerification(ctx, identifier)
	}
	return p.adapter(ctx).FindOne(ctx, storage.FindOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
}

func (p *plugin) consumeVerification(ctx context.Context, identifier string) (storage.Record, error) {
	if p.options.Runtime.ConsumeVerification != nil {
		return p.options.Runtime.ConsumeVerification(ctx, identifier)
	}
	return p.adapter(ctx).ConsumeOne(ctx, storage.ConsumeOneParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
}

func (p *plugin) deleteVerification(ctx context.Context, identifier string) error {
	if p.options.Runtime.DeleteVerification != nil {
		return p.options.Runtime.DeleteVerification(ctx, identifier)
	}
	return p.adapter(ctx).Delete(ctx, storage.DeleteParams{
		Model: "verification", Where: []storage.Where{{Field: "identifier", Value: identifier}},
	})
}

func (p *plugin) afterLogin(ctx *engine.Context, response contract.Response) (*contract.Response, error) {
	rawPrompt, ok := readSignedCookie(ctx.Request(), "oidc_login_prompt", p.options.Runtime.Secret)
	if !ok || p.options.Runtime.SessionCookie == nil {
		return nil, nil
	}
	sessionCookieName, _ := p.options.Runtime.SessionCookie(ctx.Request())
	var sessionToken string
	for _, line := range response.Headers().Values("Set-Cookie") {
		for _, parsed := range cookies.ParseSetCookieHeader(line) {
			if parsed.Name == sessionCookieName {
				sessionToken = splitSessionCookieToken(parsed.Attributes.Value)
				break
			}
		}
	}
	if sessionToken == "" {
		return nil, nil
	}
	var state *SessionState
	if p.options.Runtime.FindSession != nil {
		resolved, err := p.options.Runtime.FindSession(ctx.GoContext(), sessionToken)
		if err != nil {
			return nil, internalError(err)
		}
		state = resolved
	}
	if state == nil && p.options.Runtime.NewSession != nil {
		state = p.options.Runtime.NewSession(ctx)
	}
	if state == nil || state.User == nil || state.Session == nil {
		return nil, nil
	}
	query := map[string]string{}
	if err := json.Unmarshal([]byte(rawPrompt), &query); err != nil {
		return nil, nil
	}
	promptSet, err := ParsePrompt(query["prompt"])
	if err != nil {
		return nil, err
	}
	if promptSet.Has(PromptLogin) {
		parts := strings.Fields(query["prompt"])
		filtered := parts[:0]
		for _, part := range parts {
			if part != string(PromptLogin) {
				filtered = append(filtered, part)
			}
		}
		query["prompt"] = strings.Join(filtered, " ")
	}
	expirePromptCookie(ctx, "oidc_login_prompt")
	continued, err := p.authorizeQuery(ctx, query, state)
	if err != nil {
		return nil, err
	}
	return &continued, nil
}
