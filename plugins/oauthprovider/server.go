package oauthprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/security/ratelimit"
	"github.com/pers0na2dev/single-auth/storage"
)

// Factory binds the complete OAuth authorization server to one single-auth
// instance. A factory is intentionally single-use, matching every other root
// plugin factory.
type Factory struct {
	options Options
	mu      sync.RWMutex
	service *Server
}

// Server is the complete transport-neutral OAuth/OIDC implementation.
type Server struct {
	options  Options
	runtime  serverRuntime
	metadata *MetadataService
	consents *ConsentService
	revoke   *RevokeService
	userinfo *userInfoEndpoint
	logout   *logoutEndpoint
}

// NewFactory constructs a complete OAuth provider factory.
func NewFactory(options Options) *Factory {
	return &Factory{options: snapshotServerOptions(options)}
}

func (*Factory) PluginID() string { return PluginID }

func (factory *Factory) Schema() (storage.Schema, error) {
	if factory == nil {
		return storage.Schema{}, errors.New("oauthprovider: factory is nil")
	}
	return resolveOAuthProviderSchema(factory.options.Schema)
}

func (factory *Factory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if factory == nil {
		return engine.Plugin{}, errors.New("oauthprovider: factory is nil")
	}
	options, err := normalizeServerOptions(factory.options)
	if err != nil {
		return engine.Plugin{}, err
	}
	if !options.DisableJWTPlugin && !host.HasPlugin(jwtplugin.PluginID) {
		return engine.Plugin{}, errors.New("oauthprovider: JWT plugin is required unless DisableJWTPlugin is true")
	}
	runtime := serverRuntime{
		adapter: host.Adapter, adapterForContext: host.AdapterForContext,
		clock: host.Clock, random: host.Random, secret: host.Secret,
		resolveBaseURL: host.ResolveBaseURL, deleteSession: host.DeleteSession,
		encryptSecret: host.EncryptSecret, decryptSecret: host.DecryptSecret,
		listEndpoints: host.ListEndpoints, hasJWTPlugin: !options.DisableJWTPlugin,
		resolveSession: func(ctx *engine.Context, required bool) (*Session, error) {
			mode := singleauth.PluginSessionOptional
			if required {
				mode = singleauth.PluginSessionRequired
			}
			state, resolveErr := host.ResolveSession(ctx, mode)
			if resolveErr != nil || state == nil {
				return nil, resolveErr
			}
			return &Session{Session: state.Session, User: state.User}, nil
		},
	}
	if runtime.clock == nil {
		runtime.clock = time.Now
	}
	if runtime.random == nil {
		runtime.random = rand.Reader
	}
	service, err := newServer(options, runtime)
	if err != nil {
		return engine.Plugin{}, err
	}
	descriptor, err := service.descriptor()
	if err != nil {
		return engine.Plugin{}, err
	}
	factory.mu.Lock()
	if factory.service != nil {
		factory.mu.Unlock()
		return engine.Plugin{}, errors.New("oauthprovider: factory is already bound")
	}
	factory.service = service
	factory.mu.Unlock()
	return descriptor, nil
}

// Service returns the bound server after singleauth.New has completed.
func (factory *Factory) Service() (*Server, error) {
	if factory == nil {
		return nil, errors.New("oauthprovider: factory is nil")
	}
	factory.mu.RLock()
	service := factory.service
	factory.mu.RUnlock()
	if service == nil {
		return nil, errors.New("oauthprovider: factory is not bound")
	}
	return service, nil
}

func newServer(options Options, runtime serverRuntime) (*Server, error) {
	metadata, err := NewMetadataService(MetadataPluginOptions{
		Scopes: options.Scopes, GrantTypes: options.GrantTypes,
		AdvertisedMetadata:                     options.AdvertisedMetadata,
		AllowDynamicClientRegistration:         options.AllowDynamicClientRegistration,
		AllowUnauthenticatedClientRegistration: options.AllowUnauthenticatedClientRegistration,
		DisableJWT:                             options.DisableJWTPlugin, PairwiseSecret: options.PairwiseSecret,
		JWT: MetadataJWTOptions{JWKSPath: "/jwks", SigningAlgorithm: "EdDSA"},
	}, runtime.resolveBaseURL, false)
	if err != nil {
		return nil, err
	}
	if options.DisableJWTPlugin {
		metadata.options.jwt.SigningAlgorithm = "HS256"
	}
	consents, err := NewConsentService(ConsentOptions{
		Scopes: options.Scopes,
		Runtime: ConsentRuntime{
			Adapter: runtime.adapter, AdapterForContext: runtime.adapterForContext,
			Clock: runtime.clock,
			ResolveSession: func(ctx *engine.Context) (*ConsentSession, error) {
				state, resolveErr := runtime.resolveSession(ctx, true)
				if resolveErr != nil || state == nil {
					return nil, resolveErr
				}
				return &ConsentSession{Session: state.Session, User: state.User}, nil
			},
		},
	})
	if err != nil {
		return nil, err
	}
	server := &Server{options: options, runtime: runtime, metadata: metadata, consents: consents}
	revokeOptions := RevokeOptions{
		OpaqueAccessTokenPrefix: options.OpaqueAccessTokenPrefix,
		RefreshTokenPrefix:      options.RefreshTokenPrefix,
		ClientSecretPrefix:      options.ClientSecretPrefix,
		Issuer: &RevokeIssuerOptions{
			Random: runtime.random, AccessTokenExpiresIn: options.AccessTokenExpiresIn,
			M2MAccessTokenExpiresIn:       options.M2MAccessTokenExpiresIn,
			IDTokenExpiresIn:              options.IDTokenExpiresIn,
			RefreshTokenExpiresIn:         options.RefreshTokenExpiresIn,
			AuthorizationCodeExpiresIn:    options.AuthorizationCodeExpiresIn,
			ValidAudiences:                options.ValidAudiences,
			ServerScopes:                  options.Scopes,
			ClientCredentialDefaultScopes: options.ClientCredentialGrantDefaultScopes,
			GenerateOpaqueAccessToken:     options.GenerateOpaqueAccessToken,
			GenerateRefreshToken:          options.GenerateRefreshToken,
			SignJWT:                       server.signJWT,
			SignIDToken:                   server.signIDToken,
			ResolveSubject:                server.resolveSubject,
			CustomAccessTokenClaims:       options.CustomAccessTokenClaims,
			CustomIDTokenClaims:           options.CustomIDTokenClaims,
		},
		Runtime: RevokeRuntime{
			Adapter: runtime.adapter, AdapterForContext: runtime.adapterForContext,
			Clock: runtime.clock, StoredToken: func(_ context.Context, token string, _ RevokeTokenType) (string, error) {
				return serverHash(token), nil
			},
		},
	}
	if options.DisableJWTPlugin {
		revokeOptions.Issuer.SignJWT = nil
		revokeOptions.Runtime.VerifyClientSecret = func(_ context.Context, stored, presented string) (bool, error) {
			plain, decryptErr := server.decryptClientSecret(stored)
			if decryptErr != nil {
				return false, decryptErr
			}
			return serverConstantEqual(plain, presented), nil
		}
	} else {
		revokeOptions.Runtime.ValidateJWT = server.validateJWTDisposition
	}
	revoke, err := NewRevokeService(revokeOptions)
	if err != nil {
		return nil, err
	}
	server.revoke = revoke
	server.userinfo = &userInfoEndpoint{options: UserInfoOptions{
		Adapter: runtime.adapter, AdapterForContext: runtime.adapterForContext,
		Clock: runtime.clock, OpaqueTokenPrefix: options.OpaqueAccessTokenPrefix,
		StoredToken: func(_ context.Context, token string) (string, error) {
			return serverHash(token), nil
		},
		ValidateJWT: server.validateUserInfoJWT,
		CustomClaims: func(ctx context.Context, user storage.Record, scopes []string, claims map[string]any) (map[string]any, error) {
			if options.CustomUserInfoClaims == nil {
				return nil, nil
			}
			return options.CustomUserInfoClaims(ctx, user, scopes, claims)
		},
		ResolveSubject: server.resolveSubjectByClientID,
	}}
	server.logout = &logoutEndpoint{disableJWTPlugin: options.DisableJWTPlugin, runtime: LogoutRuntime{
		Adapter: runtime.adapter, AdapterForContext: runtime.adapterForContext,
		ResolveBaseURL: runtime.resolveBaseURL, DeleteSession: runtime.deleteSession,
		VerifyJWT: server.verifyJWT,
		DecryptClientSecret: func(_ context.Context, stored string) (string, error) {
			return server.decryptClientSecret(stored)
		},
	}}
	return server, nil
}

func (server *Server) descriptor() (engine.Plugin, error) {
	schema, err := resolveOAuthProviderSchema(server.options.Schema)
	if err != nil {
		return engine.Plugin{}, err
	}
	endpoints := []engine.Endpoint{
		{Name: "oauth2Authorize", Path: AuthorizePath, Methods: []string{http.MethodGet}, OperationID: "oauth2Authorize", Handler: server.authorize},
		{Name: "oauth2Consent", Path: ConsentPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Consent", Handler: server.authorizeConsent},
		{Name: "oauth2Continue", Path: ContinuePath, Methods: []string{http.MethodPost}, OperationID: "oauth2Continue", Handler: server.continueAuthorization},
		{Name: "oauth2Introspect", Path: IntrospectPath, Methods: []string{http.MethodPost}, OperationID: "oauth2Introspect", Handler: server.introspect},
		{Name: "registerOAuthClient", Path: RegistrationPath, Methods: []string{http.MethodPost}, OperationID: "registerOAuthClient", Handler: server.registerClient},
	}
	endpoints = append(endpoints, server.clientEndpoints()...)
	for _, descriptor := range []engine.Plugin{
		server.metadata.Descriptor(), server.consents.Descriptor(), server.revoke.Descriptor(),
		{Endpoints: []engine.Endpoint{{Name: "oauth2UserInfo", Path: UserInfoPath, Methods: []string{http.MethodGet, http.MethodPost}, OperationID: "oauth2UserInfo", Handler: server.userinfo.userInfo}}},
		{Endpoints: []engine.Endpoint{{Name: "oauth2EndSession", Path: EndSessionPath, Methods: []string{http.MethodGet}, OperationID: "oauth2EndSession", Handler: server.logout.endSession}}},
	} {
		endpoints = append(endpoints, descriptor.Endpoints...)
	}
	seenNames := make(map[string]struct{}, len(endpoints))
	seenRoutes := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		if _, exists := seenNames[endpoint.Name]; exists {
			return engine.Plugin{}, fmt.Errorf("oauthprovider: duplicate endpoint name %q", endpoint.Name)
		}
		seenNames[endpoint.Name] = struct{}{}
		for _, method := range endpoint.Methods {
			key := strings.ToUpper(method) + " " + endpoint.Path
			if _, exists := seenRoutes[key]; exists {
				return engine.Plugin{}, fmt.Errorf("oauthprovider: duplicate endpoint route %q", key)
			}
			seenRoutes[key] = struct{}{}
		}
	}
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: schema, Endpoints: endpoints,
		OnRequest: server.metadata.onRequest,
		RateLimit: []ratelimit.MatcherRule{
			{Match: func(path string) bool { return path == TokenPath }, Rule: ratelimit.Rule{Window: 60, Max: 20}},
			{Match: func(path string) bool { return path == AuthorizePath }, Rule: ratelimit.Rule{Window: 60, Max: 30}},
			{Match: func(path string) bool { return path == IntrospectPath }, Rule: ratelimit.Rule{Window: 60, Max: 100}},
			{Match: func(path string) bool { return path == RevokePath }, Rule: ratelimit.Rule{Window: 60, Max: 30}},
			{Match: func(path string) bool { return path == RegistrationPath }, Rule: ratelimit.Rule{Window: 60, Max: 5}},
			{Match: func(path string) bool { return path == UserInfoPath }, Rule: ratelimit.Rule{Window: 60, Max: 60}},
		},
	}, nil
}

func normalizeServerOptions(input Options) (Options, error) {
	options := snapshotServerOptions(input)
	if strings.TrimSpace(options.LoginPage) == "" {
		return Options{}, errors.New("oauthprovider: LoginPage is required")
	}
	if strings.TrimSpace(options.ConsentPage) == "" {
		return Options{}, errors.New("oauthprovider: ConsentPage is required")
	}
	if options.Scopes == nil {
		options.Scopes = append([]string(nil), defaultMetadataScopes...)
	}
	options.Scopes = serverUniqueStrings(options.Scopes)
	if options.GrantTypes == nil {
		options.GrantTypes = append([]GrantType(nil), defaultMetadataGrantTypes...)
	}
	if containsGrant(options.GrantTypes, GrantTypeRefreshToken) && !containsGrant(options.GrantTypes, GrantTypeAuthorizationCode) {
		return Options{}, errors.New("oauthprovider: refresh_token grant requires authorization_code grant")
	}
	for _, grant := range options.GrantTypes {
		switch grant {
		case GrantTypeAuthorizationCode, GrantTypeClientCredentials, GrantTypeRefreshToken:
		default:
			return Options{}, fmt.Errorf("oauthprovider: unsupported grant type %q", grant)
		}
	}
	if options.PairwiseSecret != "" && len(options.PairwiseSecret) < 32 {
		return Options{}, errors.New("oauthprovider: pairwise secret must contain at least 32 bytes")
	}
	if options.AccessTokenExpiresIn == 0 {
		options.AccessTokenExpiresIn = defaultAccessTokenLifetime
	}
	if options.M2MAccessTokenExpiresIn == 0 {
		options.M2MAccessTokenExpiresIn = defaultM2MTokenLifetime
	}
	if options.IDTokenExpiresIn == 0 {
		options.IDTokenExpiresIn = defaultIDTokenLifetime
	}
	if options.RefreshTokenExpiresIn == 0 {
		options.RefreshTokenExpiresIn = defaultRefreshTokenLifetime
	}
	if options.AuthorizationCodeExpiresIn == 0 {
		options.AuthorizationCodeExpiresIn = defaultCodeLifetime
	}
	if options.AccessTokenExpiresIn < 0 || options.M2MAccessTokenExpiresIn < 0 || options.IDTokenExpiresIn < 0 || options.RefreshTokenExpiresIn < 0 || options.AuthorizationCodeExpiresIn < 0 {
		return Options{}, errors.New("oauthprovider: token and code lifetimes must be positive")
	}
	allowed := options.ClientRegistrationAllowedScopes
	if allowed == nil {
		allowed = options.Scopes
	}
	configuredDefaults := append([]string(nil), options.ClientRegistrationDefaultScopes...)
	configuredDefaults = append(configuredDefaults, options.ClientCredentialGrantDefaultScopes...)
	for _, scope := range append(configuredDefaults, allowed...) {
		if !serverContains(options.Scopes, scope) {
			return Options{}, fmt.Errorf("oauthprovider: client registration scope %q is not configured", scope)
		}
	}
	return options, nil
}

func snapshotServerOptions(input Options) Options {
	result := input
	result.Scopes = cloneStringsPreserveNil(input.Scopes)
	result.GrantTypes = cloneGrantTypesPreserveNil(input.GrantTypes)
	result.ValidAudiences = cloneStringsPreserveNil(input.ValidAudiences)
	result.ClientRegistrationDefaultScopes = cloneStringsPreserveNil(input.ClientRegistrationDefaultScopes)
	result.ClientRegistrationAllowedScopes = cloneStringsPreserveNil(input.ClientRegistrationAllowedScopes)
	result.ClientCredentialGrantDefaultScopes = cloneStringsPreserveNil(input.ClientCredentialGrantDefaultScopes)
	result.AdvertisedMetadata.ScopesSupported = cloneStringsPreserveNil(input.AdvertisedMetadata.ScopesSupported)
	result.AdvertisedMetadata.ClaimsSupported = cloneStringsPreserveNil(input.AdvertisedMetadata.ClaimsSupported)
	result.Schema = input.Schema.Clone()
	if input.CachedTrustedClients != nil {
		result.CachedTrustedClients = make(map[string]struct{}, len(input.CachedTrustedClients))
		for key := range input.CachedTrustedClients {
			result.CachedTrustedClients[key] = struct{}{}
		}
	}
	return result
}

func resolveOAuthProviderSchema(extension storage.Schema) (storage.Schema, error) {
	base := OAuthProviderSchema()
	if len(extension.Models) == 0 && !extension.UsePlural {
		return base, nil
	}
	return base.Merge(extension)
}

func (server *Server) adapter(ctx context.Context) storage.TransactionAdapter {
	if server.runtime.adapterForContext != nil {
		if adapter := server.runtime.adapterForContext(ctx); adapter != nil {
			return adapter
		}
	}
	return server.runtime.adapter
}

func (server *Server) findEndpoint(name string) (engine.Endpoint, bool) {
	if server.runtime.listEndpoints == nil {
		return engine.Endpoint{}, false
	}
	for _, endpoint := range server.runtime.listEndpoints() {
		if endpoint.Name == name {
			return endpoint, true
		}
	}
	return engine.Endpoint{}, false
}

func (server *Server) callJWT(ctx *engine.Context, name string, body map[string]any) (map[string]any, error) {
	endpoint, exists := server.findEndpoint(name)
	if !exists {
		return nil, fmt.Errorf("oauthprovider: JWT endpoint %q is unavailable", name)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request := ctx.Request().WithMethod(http.MethodPost).WithTarget("/", "").WithBody(encoded).WithHeader("Content-Type", "application/json")
	response, err := engine.RunEndpointIsolated(ctx, request, endpoint)
	if err != nil {
		return nil, err
	}
	result := map[string]any{}
	if len(response.Body()) > 0 {
		decoder := json.NewDecoder(strings.NewReader(string(response.Body())))
		decoder.UseNumber()
		if err := decoder.Decode(&result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (server *Server) signJWT(ctx *engine.Context, payload map[string]any) (string, error) {
	if !server.runtime.hasJWTPlugin {
		return "", errors.New("oauthprovider: JWT plugin is disabled")
	}
	claims := cloneUserInfoMap(payload)
	if claimString(claims["iss"]) == "" {
		claims["iss"] = server.issuer(ctx.Request())
	}
	result, err := server.callJWT(ctx, "signJWT", map[string]any{"payload": claims})
	if err != nil {
		return "", err
	}
	token, _ := result["token"].(string)
	if token == "" {
		return "", errors.New("oauthprovider: JWT plugin returned an empty token")
	}
	return token, nil
}

func (server *Server) verifyJWT(ctx *engine.Context, token string) (map[string]any, error) {
	if !server.runtime.hasJWTPlugin {
		return nil, errors.New("oauthprovider: JWT plugin is disabled")
	}
	unverified, err := serverDecodeJWTClaims(token)
	if err != nil {
		return nil, err
	}
	audience := unverified["aud"]
	if audience == nil {
		return nil, errors.New("oauthprovider: JWT audience is missing")
	}
	payload, disposition, err := server.verifyJWTForAudience(ctx, token, audience)
	if err != nil {
		return nil, err
	}
	if disposition != jwtplugin.AccessTokenValid || payload == nil {
		return nil, errors.New("oauthprovider: invalid JWT")
	}
	return payload, nil
}

func (server *Server) validateJWTDisposition(ctx *engine.Context, token string) (RevokeJWTDisposition, error) {
	if strings.Count(token, ".") != 2 {
		return RevokeJWTNotJWT, nil
	}
	_, disposition, err := server.verifyOAuthAccessJWT(ctx, token)
	if err != nil {
		return RevokeJWTInactive, err
	}
	switch disposition {
	case jwtplugin.AccessTokenNotJWT:
		return RevokeJWTNotJWT, nil
	case jwtplugin.AccessTokenValid:
		return RevokeJWTValid, nil
	case jwtplugin.AccessTokenInvalidSignature, jwtplugin.AccessTokenInvalidClaims, jwtplugin.AccessTokenInactive:
		return RevokeJWTInactive, nil
	default:
		return RevokeJWTInactive, errors.New("oauthprovider: unknown JWT verification disposition")
	}
}

func (server *Server) validateUserInfoJWT(ctx *engine.Context, token string) (map[string]any, error) {
	if !server.runtime.hasJWTPlugin || strings.Count(token, ".") != 2 {
		return nil, ErrInvalidJWTAccessToken
	}
	claims, disposition, err := server.verifyOAuthAccessJWT(ctx, token)
	if err != nil || disposition != jwtplugin.AccessTokenValid || claims == nil {
		return nil, ErrInvalidJWTAccessToken
	}
	return claims, nil
}

func (server *Server) verifyOAuthAccessJWT(
	ctx *engine.Context,
	token string,
) (map[string]any, jwtplugin.AccessTokenVerification, error) {
	audience := any(append([]string(nil), server.options.ValidAudiences...))
	if len(server.options.ValidAudiences) == 0 {
		audience = server.issuer(ctx.Request())
	}
	return server.verifyJWTForAudience(ctx, token, audience)
}

func (server *Server) verifyJWTForAudience(
	ctx *engine.Context,
	token string,
	audience any,
) (map[string]any, jwtplugin.AccessTokenVerification, error) {
	issuer := server.issuer(ctx.Request())
	options := jwtplugin.Options{
		Token: jwtplugin.TokenOptions{Issuer: jwtplugin.String(issuer), Audience: audience},
		Runtime: jwtplugin.Runtime{
			Adapter: server.runtime.adapter, AdapterForContext: server.runtime.adapterForContext,
			Clock: server.runtime.clock, Secret: server.runtime.secret, BaseURL: issuer,
			ResolveBaseURL: func(*engine.Context) (string, error) { return issuer, nil },
		},
	}
	return jwtplugin.VerifyAccessToken(ctx, token, options)
}

func serverDecodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("oauthprovider: malformed JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("oauthprovider: malformed JWT payload")
	}
	claims := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&claims); err != nil || claims == nil {
		return nil, errors.New("oauthprovider: malformed JWT payload")
	}
	return claims, nil
}

func (server *Server) storeClientSecret(plain string) (string, error) {
	if server.options.DisableJWTPlugin {
		if server.runtime.encryptSecret == nil {
			return "", errors.New("oauthprovider: secret encryption is unavailable")
		}
		return server.runtime.encryptSecret([]byte(plain))
	}
	return serverHash(plain), nil
}

func (server *Server) decryptClientSecret(stored string) (string, error) {
	if server.runtime.decryptSecret == nil {
		return "", errors.New("oauthprovider: secret decryption is unavailable")
	}
	plain, err := server.runtime.decryptSecret(stored)
	return string(plain), err
}

func (server *Server) signIDToken(ctx *engine.Context, user storage.Record, client storage.Record, scopes []string, nonce, sessionID string, authTime time.Time) (string, error) {
	claims := UserNormalClaims(user, scopes)
	clientValue := server.clientFromRecord(client, false)
	userID := serverRecordString(user, "id")
	subject, err := server.resolveSubject(ctx.GoContext(), userID, client)
	if err != nil {
		return "", err
	}
	now := server.runtime.clock()
	claims["iss"] = server.issuer(ctx.Request())
	claims["sub"] = subject
	claims["aud"] = serverRecordString(client, "clientId")
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(server.options.IDTokenExpiresIn).Unix()
	claims["auth_time"] = authTime.Unix()
	claims["acr"] = "urn:mace:incommon:iap:bronze"
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if serverRecordBool(client, "enableEndSession") && sessionID != "" {
		claims["sid"] = sessionID
	}
	if server.options.CustomIDTokenClaims != nil {
		custom, customErr := server.options.CustomIDTokenClaims(ctx.GoContext(), user, append([]string(nil), scopes...), clientValue)
		if customErr != nil {
			return "", customErr
		}
		for key, value := range custom {
			claims[key] = value
		}
		// Security claims are pinned after custom values.
		claims["iss"], claims["sub"], claims["aud"] = server.issuer(ctx.Request()), subject, serverRecordString(client, "clientId")
		claims["iat"], claims["exp"] = now.Unix(), now.Add(server.options.IDTokenExpiresIn).Unix()
		if nonce != "" {
			claims["nonce"] = nonce
		}
	}
	if !server.options.DisableJWTPlugin {
		return server.signJWT(ctx, claims)
	}
	stored := serverRecordString(client, "clientSecret")
	if stored == "" {
		return "", nil
	}
	secret, err := server.decryptClientSecret(stored)
	if err != nil {
		return "", err
	}
	return serverSignHS256(claims, secret)
}

func (server *Server) issuer(request contract.Request) string {
	baseURL, err := server.runtime.resolveBaseURL(request)
	if err != nil {
		return ""
	}
	return ValidateIssuerURL(baseURL)
}

func (server *Server) resolveSubject(ctx context.Context, userID string, client storage.Record) (string, error) {
	if serverRecordString(client, "subjectType") != "pairwise" {
		return userID, nil
	}
	redirects := serverStrings(client["redirectUris"])
	if len(redirects) == 0 {
		return userID, nil
	}
	parsed, err := url.Parse(redirects[0])
	if err != nil {
		return "", err
	}
	return serverPairwiseSubject(server.options.PairwiseSecret, userID, parsed.Host), nil
}

func (server *Server) resolveSubjectByClientID(ctx context.Context, userID, clientID string) (string, error) {
	client, err := server.adapter(ctx).FindOne(ctx, storage.FindOneParams{Model: "oauthClient", Where: []storage.Where{{Field: "clientId", Value: clientID}}})
	if err != nil || client == nil {
		return userID, err
	}
	return server.resolveSubject(ctx, userID, client)
}
