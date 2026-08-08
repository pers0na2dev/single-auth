package oauthprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

const metadataCacheControl = "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"

var defaultMetadataScopes = []string{"openid", "profile", "email", "offline_access"}

var defaultMetadataGrantTypes = []GrantType{
	GrantTypeAuthorizationCode,
	GrantTypeClientCredentials,
	GrantTypeRefreshToken,
}

var baseMetadataClaims = []string{"sub", "iss", "aud", "exp", "iat", "sid", "scope", "azp"}

// MetadataOptions contains the values that change the authorization-server
// discovery document. Zero values preserve single-auth 1.6.26 defaults.
type MetadataOptions struct {
	Issuer                      string
	Scopes                      []string
	GrantTypes                  []string
	RemoteJWKSURL               string
	JWKSPath                    string
	DisableJWT                  bool
	DynamicClientRegistration   bool
	UnauthenticatedPublicClient bool
}

// MetadataAdvertisedOptions overrides the public scope and claim inventory
// without changing the scopes accepted by the authorization server.
type MetadataAdvertisedOptions struct {
	ScopesSupported []string
	ClaimsSupported []string
}

// MetadataJWTOptions is the discovery-facing subset of single-auth's JWT
// plugin options.
type MetadataJWTOptions struct {
	Issuer           string
	RemoteJWKSURL    string
	JWKSPath         string
	SigningAlgorithm string
}

// MetadataPluginOptions configures the OAuth 2.0 and OpenID Connect discovery
// surface. A nil Scopes or GrantTypes slice selects the single-auth defaults;
// a non-nil empty slice is an explicit empty set.
type MetadataPluginOptions struct {
	Scopes                                 []string
	GrantTypes                             []GrantType
	AdvertisedMetadata                     MetadataAdvertisedOptions
	AllowDynamicClientRegistration         bool
	AllowUnauthenticatedClientRegistration bool
	DisableJWT                             bool
	PairwiseSecret                         string
	JWT                                    MetadataJWTOptions
}

// ReferenceError is the configuration error class used by the OAuth
// provider package. It preserves the upstream distinction between setup
// failures and request-scoped API errors.
type ReferenceError struct{ message string }

func (err *ReferenceError) Error() string {
	if err == nil {
		return ""
	}
	return err.message
}

type normalizedMetadataOptions struct {
	scopes                                 []string
	grantTypes                             []GrantType
	advertisedScopes                       []string
	claims                                 []string
	advertisedClaims                       []string
	allowDynamicClientRegistration         bool
	allowUnauthenticatedClientRegistration bool
	disableJWT                             bool
	pairwise                               bool
	jwt                                    MetadataJWTOptions
}

// MetadataService is the immutable production discovery runtime shared by
// direct API endpoints, well-known HTTP aliases, and exported wrappers.
type MetadataService struct {
	options           normalizedMetadataOptions
	resolveBaseURL    func(contract.Request) (string, error)
	skipTrailingSlash bool
}

// MetadataFactory binds discovery to request-scoped base URL resolution from
// the root auth runtime.
type MetadataFactory struct {
	options MetadataPluginOptions
	mu      sync.RWMutex
	service *MetadataService
}

var _ singleauth.PluginFactory = (*MetadataFactory)(nil)

// NewMetadataFactory constructs the OAuth-provider metadata plugin factory.
func NewMetadataFactory(options MetadataPluginOptions) *MetadataFactory {
	return &MetadataFactory{options: snapshotMetadataPluginOptions(options)}
}

func (*MetadataFactory) PluginID() string { return PluginID }

func (*MetadataFactory) Schema() (storage.Schema, error) {
	return OAuthProviderSchema(), nil
}

func (factory *MetadataFactory) Build(host singleauth.PluginHost) (engine.Plugin, error) {
	if factory == nil {
		return engine.Plugin{}, errors.New("oauthprovider: metadata factory is nil")
	}
	service, err := NewMetadataService(
		factory.options,
		host.ResolveBaseURL,
		host.Options.Advanced.SkipTrailingSlashes,
	)
	if err != nil {
		return engine.Plugin{}, err
	}
	factory.mu.Lock()
	if factory.service != nil {
		factory.mu.Unlock()
		return engine.Plugin{}, errors.New("oauthprovider: metadata factory is already bound")
	}
	factory.service = service
	factory.mu.Unlock()
	return service.Descriptor(), nil
}

// Service returns the root-bound discovery service after singleauth.New.
func (factory *MetadataFactory) Service() (*MetadataService, error) {
	if factory == nil {
		return nil, errors.New("oauthprovider: metadata factory is nil")
	}
	factory.mu.RLock()
	service := factory.service
	factory.mu.RUnlock()
	if service == nil {
		return nil, errors.New("oauthprovider: metadata factory is not bound")
	}
	return service, nil
}

// NewMetadataService validates and snapshots a standalone discovery service.
func NewMetadataService(
	options MetadataPluginOptions,
	resolveBaseURL func(contract.Request) (string, error),
	skipTrailingSlashes bool,
) (*MetadataService, error) {
	if resolveBaseURL == nil {
		return nil, errors.New("oauthprovider: metadata base URL resolver is required")
	}
	normalized, err := normalizeMetadataPluginOptions(options)
	if err != nil {
		return nil, err
	}
	return &MetadataService{
		options: normalized, resolveBaseURL: resolveBaseURL,
		skipTrailingSlash: skipTrailingSlashes,
	}, nil
}

func normalizeMetadataPluginOptions(options MetadataPluginOptions) (normalizedMetadataOptions, error) {
	scopes := cloneStringsPreserveNil(options.Scopes)
	if scopes == nil {
		scopes = append([]string(nil), defaultMetadataScopes...)
	} else {
		filtered := make([]string, 0, len(scopes))
		for _, scope := range scopes {
			if scope != "" {
				filtered = append(filtered, scope)
			}
		}
		scopes = filtered
	}
	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = struct{}{}
	}
	advertisedScopes := cloneStringsPreserveNil(options.AdvertisedMetadata.ScopesSupported)
	for _, scope := range advertisedScopes {
		if _, exists := scopeSet[scope]; !exists {
			return normalizedMetadataOptions{}, &ReferenceError{message: fmt.Sprintf(
				"advertisedMetadata.scopes_supported %s not found in scopes", scope,
			)}
		}
	}
	claims := append([]string(nil), baseMetadataClaims...)
	if _, exists := scopeSet["email"]; exists {
		claims = append(claims, "email", "email_verified")
	}
	if _, exists := scopeSet["profile"]; exists {
		claims = append(claims, "name", "picture", "family_name", "given_name")
	}
	grants := cloneGrantTypesPreserveNil(options.GrantTypes)
	if grants == nil {
		grants = append([]GrantType(nil), defaultMetadataGrantTypes...)
	}
	if containsGrant(grants, GrantTypeRefreshToken) && !containsGrant(grants, GrantTypeAuthorizationCode) {
		return normalizedMetadataOptions{}, &ReferenceError{
			message: "refresh_token grant requires authorization_code grant",
		}
	}
	if options.PairwiseSecret != "" && len(options.PairwiseSecret) < 32 {
		return normalizedMetadataOptions{}, &ReferenceError{
			message: "pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security",
		}
	}
	jwtOptions := options.JWT
	if jwtOptions.JWKSPath == "" {
		jwtOptions.JWKSPath = "/jwks"
	}
	if jwtOptions.SigningAlgorithm == "" {
		jwtOptions.SigningAlgorithm = "EdDSA"
	}
	return normalizedMetadataOptions{
		scopes: scopes, grantTypes: grants,
		advertisedScopes:                       cloneStringsPreserveNil(advertisedScopes),
		claims:                                 claims,
		advertisedClaims:                       cloneStringsPreserveNil(options.AdvertisedMetadata.ClaimsSupported),
		allowDynamicClientRegistration:         options.AllowDynamicClientRegistration,
		allowUnauthenticatedClientRegistration: options.AllowUnauthenticatedClientRegistration,
		disableJWT:                             options.DisableJWT,
		pairwise:                               options.PairwiseSecret != "",
		jwt:                                    jwtOptions,
	}, nil
}

func snapshotMetadataPluginOptions(source MetadataPluginOptions) MetadataPluginOptions {
	result := source
	result.Scopes = cloneStringsPreserveNil(source.Scopes)
	result.GrantTypes = cloneGrantTypesPreserveNil(source.GrantTypes)
	result.AdvertisedMetadata.ScopesSupported = cloneStringsPreserveNil(
		source.AdvertisedMetadata.ScopesSupported,
	)
	result.AdvertisedMetadata.ClaimsSupported = cloneStringsPreserveNil(
		source.AdvertisedMetadata.ClaimsSupported,
	)
	return result
}

func cloneStringsPreserveNil(source []string) []string {
	if source == nil {
		return nil
	}
	return append([]string{}, source...)
}

func cloneGrantTypesPreserveNil(source []GrantType) []GrantType {
	if source == nil {
		return nil
	}
	return append([]GrantType{}, source...)
}

func containsGrant(values []GrantType, target GrantType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// ValidateIssuerURL applies the RFC 9207 issuer normalization used by Better
// Auth: non-loopback HTTP issuers are upgraded to HTTPS, query and fragment
// components are removed, and a trailing root slash is omitted.
func ValidateIssuerURL(issuer string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return issuer
	}
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		parsed.Scheme = "https"
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	return strings.TrimSuffix(parsed.String(), "/")
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// AuthServerMetadata renders the single-auth 1.6.26 RFC 8414 discovery
// document for a request-resolved auth base URL.
func AuthServerMetadata(baseURL string, options MetadataOptions) map[string]any {
	baseURL = strings.TrimSuffix(baseURL, "/")
	issuer := options.Issuer
	if issuer == "" {
		issuer = baseURL
	}
	scopes := cloneStringsPreserveNil(options.Scopes)
	grants := cloneStringsPreserveNil(options.GrantTypes)
	if grants == nil {
		grants = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	authMethods := []string{"client_secret_basic", "client_secret_post"}
	if options.UnauthenticatedPublicClient {
		authMethods = append([]string{"none"}, authMethods...)
	}
	metadata := map[string]any{
		"issuer":                                         ValidateIssuerURL(issuer),
		"authorization_endpoint":                         baseURL + "/oauth2/authorize",
		"token_endpoint":                                 baseURL + "/oauth2/token",
		"introspection_endpoint":                         baseURL + "/oauth2/introspect",
		"revocation_endpoint":                            baseURL + "/oauth2/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          grants,
		"token_endpoint_auth_methods_supported":          authMethods,
		"introspection_endpoint_auth_methods_supported":  []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":     []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
	}
	if scopes != nil {
		metadata["scopes_supported"] = scopes
	}
	if !options.DisableJWT {
		jwksURL := options.RemoteJWKSURL
		if jwksURL == "" {
			jwksPath := options.JWKSPath
			if jwksPath == "" {
				jwksPath = "/jwks"
			}
			jwksURL = baseURL + jwksPath
		}
		metadata["jwks_uri"] = jwksURL
	}
	if options.DynamicClientRegistration {
		metadata["registration_endpoint"] = baseURL + "/oauth2/register"
	}
	hasAuthorizationCode := false
	for _, grant := range grants {
		if grant == "authorization_code" {
			hasAuthorizationCode = true
			break
		}
	}
	if !hasAuthorizationCode {
		metadata["response_types_supported"] = []string{}
	}
	return metadata
}

// OIDCServerMetadata adds the OpenID Connect discovery fields to the RFC 8414
// authorization-server document.
func OIDCServerMetadata(
	baseURL string,
	options MetadataOptions,
	claims []string,
	pairwise bool,
	signingAlgorithm string,
) map[string]any {
	metadata := AuthServerMetadata(baseURL, options)
	metadata["claims_supported"] = append([]string{}, claims...)
	metadata["userinfo_endpoint"] = strings.TrimSuffix(baseURL, "/") + "/oauth2/userinfo"
	subjectTypes := []string{"public"}
	if pairwise {
		subjectTypes = append(subjectTypes, "pairwise")
	}
	metadata["subject_types_supported"] = subjectTypes
	if signingAlgorithm == "" {
		signingAlgorithm = "EdDSA"
	}
	metadata["id_token_signing_alg_values_supported"] = []string{signingAlgorithm}
	metadata["end_session_endpoint"] = strings.TrimSuffix(baseURL, "/") + EndSessionPath
	metadata["acr_values_supported"] = []string{"urn:mace:incommon:iap:bronze"}
	metadata["prompt_values_supported"] = []string{
		"login", "consent", "create", "select_account", "none",
	}
	return metadata
}

// Descriptor exposes both server-only direct API endpoints and the public
// issuer-derived well-known aliases.
func (service *MetadataService) Descriptor() engine.Plugin {
	return engine.Plugin{
		ID: PluginID, Version: Version, Schema: OAuthProviderSchema(),
		Endpoints: []engine.Endpoint{
			{
				Name: "getOAuthServerConfig", Path: "/.well-known/oauth-authorization-server",
				Methods: []string{"GET"}, ServerOnly: true,
				OperationID: "getOAuthServerConfig", Handler: service.getOAuthServerConfig,
			},
			{
				Name: "getOpenIdConfig", Path: "/.well-known/openid-configuration",
				Methods: []string{"GET"}, ServerOnly: true,
				OperationID: "getOpenIdConfig", Handler: service.getOpenIDConfig,
			},
		},
		OnRequest: service.onRequest,
	}
}

func (service *MetadataService) getOAuthServerConfig(ctx *engine.Context) (contract.Response, error) {
	metadata, err := service.OAuthServerMetadata(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, metadata)
}

func (service *MetadataService) getOpenIDConfig(ctx *engine.Context) (contract.Response, error) {
	metadata, err := service.OpenIDConfig(ctx.Request())
	if err != nil {
		return contract.Response{}, err
	}
	return contract.JSONResponse(contract.StatusOK, metadata)
}

// OAuthServerMetadata returns the request-resolved OAuth or OIDC discovery
// document used by getOAuthServerConfig.
func (service *MetadataService) OAuthServerMetadata(request contract.Request) (map[string]any, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: metadata service is nil")
	}
	baseURL, err := service.resolveBaseURL(request)
	if err != nil {
		return nil, err
	}
	if service.supportsOpenID() {
		return service.openIDMetadata(baseURL), nil
	}
	return service.authorizationMetadata(baseURL), nil
}

// OpenIDConfig returns the request-resolved OIDC discovery document or the
// same typed 404 emitted by single-auth when the openid scope is absent.
func (service *MetadataService) OpenIDConfig(request contract.Request) (map[string]any, error) {
	if service == nil {
		return nil, errors.New("oauthprovider: metadata service is nil")
	}
	if !service.supportsOpenID() {
		return nil, contract.NewAPIError(contract.StatusNotFound, "NOT_FOUND", "Not Found")
	}
	baseURL, err := service.resolveBaseURL(request)
	if err != nil {
		return nil, err
	}
	return service.openIDMetadata(baseURL), nil
}

func (service *MetadataService) supportsOpenID() bool {
	for _, scope := range service.options.scopes {
		if scope == "openid" {
			return true
		}
	}
	return false
}

func (service *MetadataService) metadataOptions(baseURL string) MetadataOptions {
	issuer := service.options.jwt.Issuer
	if service.options.disableJWT {
		issuer = baseURL
	}
	scopes := service.options.advertisedScopes
	if scopes == nil {
		scopes = service.options.scopes
	}
	grants := make([]string, len(service.options.grantTypes))
	for index, grant := range service.options.grantTypes {
		grants[index] = string(grant)
	}
	return MetadataOptions{
		Issuer: issuer, Scopes: append([]string{}, scopes...), GrantTypes: grants,
		RemoteJWKSURL:               service.options.jwt.RemoteJWKSURL,
		JWKSPath:                    service.options.jwt.JWKSPath,
		DisableJWT:                  service.options.disableJWT,
		DynamicClientRegistration:   service.options.allowDynamicClientRegistration,
		UnauthenticatedPublicClient: service.options.allowUnauthenticatedClientRegistration,
	}
}

func (service *MetadataService) authorizationMetadata(baseURL string) map[string]any {
	return AuthServerMetadata(baseURL, service.metadataOptions(baseURL))
}

func (service *MetadataService) openIDMetadata(baseURL string) map[string]any {
	claims := service.options.advertisedClaims
	if claims == nil {
		claims = service.options.claims
	}
	algorithm := service.options.jwt.SigningAlgorithm
	if service.options.disableJWT {
		algorithm = "HS256"
	}
	return OIDCServerMetadata(
		baseURL,
		service.metadataOptions(baseURL),
		claims,
		service.options.pairwise,
		algorithm,
	)
}

func (service *MetadataService) onRequest(ctx *engine.Context) (engine.OnRequestResult, error) {
	if service == nil || ctx == nil {
		return engine.OnRequestResult{}, nil
	}
	request := ctx.Request()
	baseURL, err := service.resolveBaseURL(request)
	if err != nil {
		return engine.OnRequestResult{}, err
	}
	issuer := service.options.jwt.Issuer
	if service.options.disableJWT || issuer == "" {
		issuer = baseURL
	}
	issuerPath := issuerMetadataPath(issuer, baseURL)
	requestPath := request.RawPath()
	if queryIndex := strings.IndexByte(requestPath, '?'); queryIndex >= 0 {
		requestPath = requestPath[:queryIndex]
	}
	if service.skipTrailingSlash {
		requestPath = strings.TrimRight(requestPath, "/")
		if requestPath == "" {
			requestPath = "/"
		}
	}
	authPaths := map[string]struct{}{
		"/.well-known/oauth-authorization-server" + issuerPath: {},
		issuerPath + "/.well-known/oauth-authorization-server": {},
	}
	_, authorizationMatch := authPaths[requestPath]
	openIDPath := issuerPath + "/.well-known/openid-configuration"
	openIDMatch := service.supportsOpenID() && requestPath == openIDPath
	if !authorizationMatch && !openIDMatch {
		return engine.OnRequestResult{}, nil
	}
	method := strings.ToUpper(request.Method())
	if method != "GET" && method != "HEAD" {
		response := contract.NewResponse(
			contract.StatusMethodNotAllowed,
			contract.NewHeaders(contract.HeaderField{Name: "Allow", Value: "GET, HEAD"}),
			nil,
		)
		return engine.OnRequestResult{Response: &response}, nil
	}
	metadata := service.authorizationMetadata(baseURL)
	if openIDMatch || (authorizationMatch && service.supportsOpenID()) {
		metadata = service.openIDMetadata(baseURL)
	}
	response, err := MetadataResponse(metadata)
	if err != nil {
		return engine.OnRequestResult{}, err
	}
	if method == "HEAD" {
		response = response.WithBody(nil)
	}
	return engine.OnRequestResult{Response: &response}, nil
}

func issuerMetadataPath(issuer, fallback string) string {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		parsed, err = url.Parse(fallback)
	}
	if err != nil || parsed == nil {
		return ""
	}
	path := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if path == "/" {
		return ""
	}
	return path
}

// MetadataResponse serializes a discovery document with single-auth's exact
// cache and content-type headers. Caller headers are preserved except that
// Content-Type is always application/json.
func MetadataResponse(body any, extraHeaders ...contract.Headers) (contract.Response, error) {
	headers := contract.Headers{}
	if len(extraHeaders) > 0 {
		headers = extraHeaders[0].Clone()
	}
	if _, exists := headers.Get("Cache-Control"); !exists {
		headers.Set("Cache-Control", metadataCacheControl)
	}
	headers.Set("Content-Type", "application/json")
	encoded, err := json.Marshal(body)
	if err != nil {
		return contract.Response{}, err
	}
	return contract.NewResponse(contract.StatusOK, headers, encoded), nil
}

// MetadataDocumentSource is implemented by MetadataService and custom
// discovery providers used by exported wrapper handlers.
type MetadataDocumentSource interface {
	OAuthServerMetadata(contract.Request) (map[string]any, error)
	OpenIDConfig(contract.Request) (map[string]any, error)
}

// MetadataWrapperOptions supplies response headers to an exported discovery
// wrapper.
type MetadataWrapperOptions struct{ Headers contract.Headers }

// OAuthProviderAuthServerMetadata is the transport-neutral counterpart of
// oauthProviderAuthServerMetadata.
func OAuthProviderAuthServerMetadata(
	source MetadataDocumentSource,
	options ...MetadataWrapperOptions,
) func(contract.Request) (contract.Response, error) {
	return func(request contract.Request) (contract.Response, error) {
		if source == nil {
			return contract.Response{}, errors.New("oauthprovider: metadata source is nil")
		}
		metadata, err := source.OAuthServerMetadata(request)
		if err != nil {
			return contract.Response{}, err
		}
		return MetadataResponse(metadata, metadataWrapperHeaders(options))
	}
}

// OAuthProviderOpenIDConfigMetadata is the transport-neutral counterpart of
// oauthProviderOpenIdConfigMetadata.
func OAuthProviderOpenIDConfigMetadata(
	source MetadataDocumentSource,
	options ...MetadataWrapperOptions,
) func(contract.Request) (contract.Response, error) {
	return func(request contract.Request) (contract.Response, error) {
		if source == nil {
			return contract.Response{}, errors.New("oauthprovider: metadata source is nil")
		}
		metadata, err := source.OpenIDConfig(request)
		if err != nil {
			return contract.Response{}, err
		}
		return MetadataResponse(metadata, metadataWrapperHeaders(options))
	}
}

func metadataWrapperHeaders(options []MetadataWrapperOptions) contract.Headers {
	if len(options) == 0 {
		return contract.Headers{}
	}
	return options[0].Headers.Clone()
}
