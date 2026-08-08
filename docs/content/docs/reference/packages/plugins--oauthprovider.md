---
title: "github.com/pers0na2dev/single-auth/plugins/oauthprovider"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/oauthprovider.

- Import path: `github.com/pers0na2dev/single-auth/plugins/oauthprovider`
- Package name: `oauthprovider`

Package oauthprovider contains the production OAuth 2.0/OIDC provider
metadata surface shared by single-auth HTTP hosts. The remaining provider
endpoints are ported independently; this package deliberately does not
claim that they exist merely because discovery metadata can be rendered.

## Constants

```go
const (
	GetConsentPath    = "/oauth2/get-consent"
	GetConsentsPath   = "/oauth2/get-consents"
	UpdateConsentPath = "/oauth2/update-consent"
	DeleteConsentPath = "/oauth2/delete-consent"
)
```

```go
const (
	EndSessionPath = "/oauth2/end-session"
	PluginID       = "oauth-provider"
	Version        = "1.6.26"
)
```

```go
const (
	MCPAuthorizePath    = "/oauth2/authorize"
	MCPConsentPath      = "/oauth2/consent"
	MCPRegistrationPath = "/oauth2/register"
	MCPTokenPath        = "/oauth2/token"
)
```

```go
const (
	AuthorizePath       = "/oauth2/authorize"
	AuthorizationPath   = AuthorizePath
	ConsentPath         = "/oauth2/consent"
	ContinuePath        = "/oauth2/continue"
	TokenPath           = "/oauth2/token"
	IntrospectPath      = "/oauth2/introspect"
	RegistrationPath    = "/oauth2/register"
	CreateClientPath    = "/oauth2/create-client"
	GetClientPath       = "/oauth2/get-client"
	GetPublicClientPath = "/oauth2/public-client"
	GetClientsPath      = "/oauth2/get-clients"
	UpdateClientPath    = "/oauth2/update-client"
	RotateSecretPath    = "/oauth2/client/rotate-secret"
	DeleteClientPath    = "/oauth2/delete-client"
)
```

```go
const (
	SignedQueryParameterNameParam = "ba_param"

	PostLoginClearedParam = "ba_pl"
)
```

MCPAccessTokenClaims is the request-context key populated by Guard.

```go
const MCPAccessTokenClaims = "oauthprovider:mcp-access-token-claims"
```

```go
const RevokeIssuerTokenPath = "/oauth2/token"
```

```go
const RevokePath = "/oauth2/revoke"
```

SignedQueryIssuedAtParam is the single-auth signed-query issuance field.

```go
const SignedQueryIssuedAtParam = "ba_iat"
```

```go
const UserInfoPath = "/oauth2/userinfo"
```

## Variables

```go
var ErrInvalidBasicAuthorization = errors.New("invalid authorization header format")
```

ErrInvalidJWTAccessToken tells the shared access-token validator to continue
with opaque-token lookup. Other verifier errors are treated as internal
failures, matching single-auth's APIError-versus-Error distinction.

```go
var ErrInvalidJWTAccessToken = errors.New("oauthprovider: invalid JWT access token")
```

## Functions

### `AuthServerMetadata`

AuthServerMetadata renders the single-auth 1.6.26 RFC 8414 discovery
document for a request-resolved auth base URL.

```go
func AuthServerMetadata(baseURL string, options MetadataOptions) map[string]any
```

### `BuildSignedOAuthQuery`

BuildSignedOAuthQuery keeps only the signature, declarations, and declared
signed fields. Pair order and repeated fields are preserved.

```go
func BuildSignedOAuthQuery(search string) (string, bool)
```

### `CanonicalizeOAuthQueryParams`

CanonicalizeOAuthQueryParams serializes query pairs sorted first by key and
then by value, retaining repeated parameters.

```go
func CanonicalizeOAuthQueryParams(params url.Values) string
```

### `GetSignedQueryIssuedAt`

GetSignedQueryIssuedAt reads single-auth's positive finite ba_iat epoch
milliseconds value from a serialized query.

```go
func GetSignedQueryIssuedAt(oauthQuery string) (time.Time, bool)
```

### `IsSafeURL`

IsSafeURL is the boolean form of ValidateSafeURL.

```go
func IsSafeURL(value string) bool
```

### `MCPWWWAuthenticate`

MCPWWWAuthenticate renders single-auth 1.6.26's exact RFC 9728 challenge.
Every URL audience has its own Bearer challenge and array entries are joined
with comma-space in declaration order.

```go
func MCPWWWAuthenticate(resource any, mappings map[string]string) (string, error)
```

### `MetadataResponse`

MetadataResponse serializes a discovery document with single-auth's exact
cache and content-type headers. Caller headers are preserved except that
Content-Type is always application/json.

```go
func MetadataResponse(body any, extraHeaders ...contract.Headers) (contract.Response, error)
```

### `NewConsentPlugin`

NewConsentPlugin constructs the four transport-neutral consent management
endpoints. The descriptor runs unchanged through net/http, fasthttp, Fiber,
and direct API dispatch.

```go
func NewConsentPlugin(options ConsentOptions) (engine.Plugin, error)
```

### `NewLogoutPlugin`

NewLogoutPlugin constructs the transport-neutral production endpoint. The
returned descriptor can be served by net/http, fasthttp and Fiber through
the standard single-auth transports.

```go
func NewLogoutPlugin(options LogoutOptions) (engine.Plugin, error)
```

### `NewRevokePlugin`

NewRevokePlugin constructs the descriptor used unchanged by net/http,
fasthttp, Fiber, and direct API dispatch.

```go
func NewRevokePlugin(options RevokeOptions) (engine.Plugin, error)
```

### `NewUserInfoPlugin`

NewUserInfoPlugin constructs the transport-neutral OAuth Provider userinfo
endpoint. The descriptor is served unchanged by net/http, fasthttp, Fiber,
and direct API dispatch.

```go
func NewUserInfoPlugin(options UserInfoOptions) (engine.Plugin, error)
```

### `NormalizeTimestampValue`

NormalizeTimestampValue implements the timestamp normalization used by the
single-auth OAuth provider. It accepts dates, epoch milliseconds, numeric
millisecond strings, and common ISO/RFC date strings.

```go
func NormalizeTimestampValue(value any) (time.Time, bool)
```

### `OAuthProviderAuthServerMetadata`

OAuthProviderAuthServerMetadata is the transport-neutral counterpart of
oauthProviderAuthServerMetadata.

```go
func OAuthProviderAuthServerMetadata(
	source MetadataDocumentSource,
	options ...MetadataWrapperOptions,
) func(contract.Request) (contract.Response, error)
```

### `OAuthProviderOpenIDConfigMetadata`

OAuthProviderOpenIDConfigMetadata is the transport-neutral counterpart of
oauthProviderOpenIdConfigMetadata.

```go
func OAuthProviderOpenIDConfigMetadata(
	source MetadataDocumentSource,
	options ...MetadataWrapperOptions,
) func(contract.Request) (contract.Response, error)
```

### `OAuthProviderSchema`

OAuthProviderSchema returns the single-auth OAuth provider persistence
models. A fresh schema is returned on every call so plugin composition may
safely customize it.

```go
func OAuthProviderSchema() storage.Schema
```

### `OIDCServerMetadata`

OIDCServerMetadata adds the OpenID Connect discovery fields to the RFC 8414
authorization-server document.

```go
func OIDCServerMetadata(
	baseURL string,
	options MetadataOptions,
	claims []string,
	pairwise bool,
	signingAlgorithm string,
) map[string]any
```

### `RemovePromptFromQuery`

RemovePromptFromQuery returns a deep copy of query with the first matching
space-delimited prompt removed. The input is never mutated.

```go
func RemovePromptFromQuery(query url.Values, prompt string) url.Values
```

### `ResolveSessionAuthTime`

ResolveSessionAuthTime reads createdAt or created_at from a direct session
object, then from a nested session object. updatedAt fields are deliberately
ignored, matching single-auth.

```go
func ResolveSessionAuthTime(value any) (time.Time, bool)
```

### `SanitizeDynamicRegistration`

SanitizeDynamicRegistration removes the admin-only enable_end_session input
while retaining ordinary dynamic-registration metadata. single-auth never
permits a self-registered RP to grant itself logout authority.

```go
func SanitizeDynamicRegistration(input map[string]any) map[string]any
```

### `SearchParamsToQuery`

SearchParamsToQuery converts URL values into single-auth's query shape:
singleton parameters are strings and repeated parameters are string slices.

```go
func SearchParamsToQuery(params url.Values) map[string]any
```

### `SetSignedOAuthQueryParameterNames`

SetSignedOAuthQueryParameterNames replaces ba_param declarations with the
sorted unique names of the current parameters plus ba_param itself.

```go
func SetSignedOAuthQueryParameterNames(params url.Values)
```

### `UserNormalClaims`

UserNormalClaims selects single-auth's standard OIDC claims for scopes.

```go
func UserNormalClaims(user storage.Record, scopes []string) map[string]any
```

### `ValidateIssuerURL`

ValidateIssuerURL applies the RFC 9207 issuer normalization used by Better
Auth: non-loopback HTTP issuers are upgraded to HTTPS, query and fragment
components are removed, and a trailing root slash is omitted.

```go
func ValidateIssuerURL(issuer string) string
```

### `ValidateSafeURL`

ValidateSafeURL is the OAuth Provider export of single-auth's shared
SafeUrlSchema policy. It permits HTTPS and custom application schemes,
permits HTTP only on loopback hosts, and rejects executable schemes and
fragments.

```go
func ValidateSafeURL(value string) error
```

## Types

### `AuthMethod`

AuthMethod is a confidential-client authentication method.

```go
type AuthMethod string
```

## Constants associated with `AuthMethod`

```go
const (
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"
	AuthMethodClientSecretPost  AuthMethod = "client_secret_post"
)
```

### `Client`

Client is the native Go representation of an OAuth provider client. Fields
use RFC 7591 JSON names on the wire and the existing oauthClient schema in
storage.

```go
type Client struct {
	ClientID                string         `json:"client_id,omitempty"`
	ClientSecret            string         `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64          `json:"client_secret_expires_at,omitempty"`
	Scope                   string         `json:"scope,omitempty"`
	UserID                  string         `json:"user_id,omitempty"`
	ClientIDIssuedAt        int64          `json:"client_id_issued_at,omitempty"`
	ClientName              string         `json:"client_name,omitempty"`
	ClientURI               string         `json:"client_uri,omitempty"`
	LogoURI                 string         `json:"logo_uri,omitempty"`
	Contacts                []string       `json:"contacts,omitempty"`
	TOSURI                  string         `json:"tos_uri,omitempty"`
	PolicyURI               string         `json:"policy_uri,omitempty"`
	SoftwareID              string         `json:"software_id,omitempty"`
	SoftwareVersion         string         `json:"software_version,omitempty"`
	SoftwareStatement       string         `json:"software_statement,omitempty"`
	RedirectURIs            []string       `json:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs  []string       `json:"post_logout_redirect_uris,omitempty"`
	TokenEndpointAuthMethod AuthMethod     `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []GrantType    `json:"grant_types,omitempty"`
	ResponseTypes           []string       `json:"response_types,omitempty"`
	Public                  bool           `json:"public,omitempty"`
	Type                    string         `json:"type,omitempty"`
	Disabled                bool           `json:"disabled,omitempty"`
	SkipConsent             bool           `json:"skip_consent,omitempty"`
	EnableEndSession        bool           `json:"enable_end_session,omitempty"`
	RequirePKCE             *bool          `json:"require_pkce,omitempty"`
	SubjectType             string         `json:"subject_type,omitempty"`
	ReferenceID             string         `json:"reference_id,omitempty"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}
```

### `ClientCredentials`

ClientCredentials is the RFC 7617 Basic representation consumed by OAuth
client authentication endpoints.

```go
type ClientCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
```

## Constructors and functions for `ClientCredentials`

### `BasicToClientCredentials`

BasicToClientCredentials parses single-auth's Basic authorization format.
A non-Basic header returns (nil, nil); malformed Basic data returns
ErrInvalidBasicAuthorization. Only the first colon separates the ID so all
remaining colons stay in the client secret.

```go
func BasicToClientCredentials(authorization string) (*ClientCredentials, error)
```

### `ClientPrivilegeAction`

```go
type ClientPrivilegeAction string
```

## Constants associated with `ClientPrivilegeAction`

```go
const (
	ClientPrivilegeCreate ClientPrivilegeAction = "create"
	ClientPrivilegeRead   ClientPrivilegeAction = "read"
	ClientPrivilegeUpdate ClientPrivilegeAction = "update"
	ClientPrivilegeDelete ClientPrivilegeAction = "delete"
	ClientPrivilegeList   ClientPrivilegeAction = "list"
	ClientPrivilegeRotate ClientPrivilegeAction = "rotate"
)
```

### `ClientPrivilegeFunc`

```go
type ClientPrivilegeFunc func(context.Context, ClientPrivilegeAction, *Session) (bool, error)
```

### `ClientReferenceFunc`

```go
type ClientReferenceFunc func(context.Context, *Session) (string, error)
```

### `ConsentFactory`

ConsentFactory delays runtime binding until single-auth has created the
final adapter and core session implementation.

```go
type ConsentFactory struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `ConsentFactory`

### `NewConsentFactory`

NewConsentFactory binds consent endpoints to the root single-auth runtime.
The returned factory also exposes the trusted CreateConsent method after it
has been bound by singleauth.New.

```go
func NewConsentFactory(options ConsentOptions) *ConsentFactory
```

## Methods on `ConsentFactory`

### `Build`

```go
func (factory *ConsentFactory) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `CreateConsent`

CreateConsent persists a trusted server-side consent using the runtime bound
by singleauth.New.

```go
func (factory *ConsentFactory) CreateConsent(
	ctx context.Context,
	input CreateConsentInput,
) (storage.Record, error)
```

### `PluginID`

```go
func (*ConsentFactory) PluginID() string
```

### `Schema`

```go
func (*ConsentFactory) Schema() (storage.Schema, error)
```

### `ConsentOptions`

ConsentOptions configures OAuth consent persistence and the global fallback
scope set. A client's own scopes take precedence when they are present.

```go
type ConsentOptions struct {
	Scopes  []string
	Runtime ConsentRuntime
}
```

### `ConsentRuntime`

ConsentRuntime contains dependencies injected by NewConsentFactory. It is
public so a transport-neutral plugin can also be assembled independently.

```go
type ConsentRuntime struct {
	Adapter           storage.Adapter
	AdapterForContext func(context.Context) storage.TransactionAdapter
	Clock             func() time.Time
	ResolveSession    ConsentSessionResolver
}
```

### `ConsentService`

ConsentService owns the production persistence operations shared by HTTP
endpoints and trusted server-side callers.

```go
type ConsentService struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `ConsentService`

### `NewConsentService`

NewConsentService validates and snapshots a production consent service.

```go
func NewConsentService(input ConsentOptions) (*ConsentService, error)
```

## Methods on `ConsentService`

### `CreateConsent`

CreateConsent persists a grant with the same second-precision timestamps as
single-auth's OAuth provider.

```go
func (service *ConsentService) CreateConsent(
	ctx context.Context,
	input CreateConsentInput,
) (storage.Record, error)
```

### `DeleteConsent`

DeleteConsent removes a consent only when it belongs to the supplied user.

```go
func (service *ConsentService) DeleteConsent(
	ctx context.Context,
	userID, id string,
) error
```

### `Descriptor`

Descriptor returns an isolated OAuth-provider descriptor containing the
consent-management surface.

```go
func (service *ConsentService) Descriptor() engine.Plugin
```

### `GetConsent`

GetConsent returns a consent only to its owning user.

```go
func (service *ConsentService) GetConsent(
	ctx context.Context,
	userID, id string,
) (storage.Record, error)
```

### `ListConsents`

ListConsents preserves adapter insertion order, matching findMany upstream.

```go
func (service *ConsentService) ListConsents(
	ctx context.Context,
	userID string,
) ([]storage.Record, error)
```

### `UpdateConsent`

UpdateConsent checks the client-specific scope set before mutating a grant.

```go
func (service *ConsentService) UpdateConsent(
	ctx context.Context,
	input UpdateConsentInput,
) (storage.Record, error)
```

### `ConsentSession`

ConsentSession is the authenticated session/user pair required by the
consent-management endpoints.

```go
type ConsentSession struct {
	Session storage.Record
	User    storage.Record
}
```

### `ConsentSessionResolver`

ConsentSessionResolver resolves the same required session used by Better
Auth's sessionMiddleware. Implementations must be safe for concurrent use.

```go
type ConsentSessionResolver func(*engine.Context) (*ConsentSession, error)
```

### `CreateConsentInput`

CreateConsentInput is the server-side input used to persist a grant. It is
intentionally not exposed as an HTTP endpoint: upstream creates grants from
trusted server flows and only exposes management endpoints to the browser.

```go
type CreateConsentInput struct {
	ClientID    string
	Scopes      []string
	UserID      string
	ReferenceID string
}
```

### `CustomAccessTokenClaimsFunc`

```go
type CustomAccessTokenClaimsFunc func(context.Context, storage.Record, []string, Client, string) (map[string]any, error)
```

### `CustomIDTokenClaimsFunc`

```go
type CustomIDTokenClaimsFunc func(context.Context, storage.Record, []string, Client) (map[string]any, error)
```

### `CustomUserInfoClaimsFunc`

```go
type CustomUserInfoClaimsFunc func(context.Context, storage.Record, []string, map[string]any) (map[string]any, error)
```

### `Factory`

Factory binds the complete OAuth authorization server to one single-auth
instance. A factory is intentionally single-use, matching every other root
plugin factory.

```go
type Factory struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Factory`

### `NewFactory`

NewFactory constructs a complete OAuth provider factory.

```go
func NewFactory(options Options) *Factory
```

## Methods on `Factory`

### `Build`

```go
func (factory *Factory) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `PluginID`

```go
func (*Factory) PluginID() string
```

### `Schema`

```go
func (factory *Factory) Schema() (storage.Schema, error)
```

### `Service`

Service returns the bound server after singleauth.New has completed.

```go
func (factory *Factory) Service() (*Server, error)
```

### `GrantType`

GrantType is a grant type accepted by the OAuth token endpoint.

```go
type GrantType string
```

## Constants associated with `GrantType`

```go
const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)
```

### `LogoutJWTVerifier`

LogoutJWTVerifier verifies the compact JWS signature used by the configured
JWT plugin and returns its claims. Claim validation that is specific to
RP-Initiated Logout (issuer, audience and sid) remains in this package.

```go
type LogoutJWTVerifier func(*engine.Context, string) (map[string]any, error)
```

### `LogoutOptions`

LogoutOptions controls the two ID-token verification modes supported by the
upstream OAuth provider.

```go
type LogoutOptions struct {
	DisableJWTPlugin bool
	Runtime          LogoutRuntime
}
```

### `LogoutRuntime`

LogoutRuntime is the persistence and cryptographic surface needed by the
RP-Initiated Logout endpoint.

```go
type LogoutRuntime struct {
	Adapter             storage.Adapter
	AdapterForContext   func(context.Context) storage.TransactionAdapter
	Issuer              string
	ResolveBaseURL      func(contract.Request) (string, error)
	VerifyJWT           LogoutJWTVerifier
	DecryptClientSecret func(context.Context, string) (string, error)
	DeleteSession       func(context.Context, string) error
}
```

### `MCPAuthorizationFactory`

MCPAuthorizationFactory binds the OAuth server to a root single-auth
runtime and embeds the matching JWT/JWKS endpoint.

```go
type MCPAuthorizationFactory struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MCPAuthorizationFactory`

### `NewMCPAuthorizationFactory`

NewMCPAuthorizationFactory constructs a root-bound MCP OAuth server.

```go
func NewMCPAuthorizationFactory(options MCPAuthorizationOptions) *MCPAuthorizationFactory
```

## Methods on `MCPAuthorizationFactory`

### `Build`

```go
func (factory *MCPAuthorizationFactory) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `PluginID`

```go
func (*MCPAuthorizationFactory) PluginID() string
```

### `Schema`

```go
func (*MCPAuthorizationFactory) Schema() (storage.Schema, error)
```

### `Service`

Service returns the bound production service after singleauth.New.

```go
func (factory *MCPAuthorizationFactory) Service() (*MCPAuthorizationService, error)
```

### `MCPAuthorizationOptions`

MCPAuthorizationOptions configures the OAuth 2.1 authorization server used
by MCP clients. Dynamic public clients always use PKCE S256.

```go
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
```

### `MCPAuthorizationRuntime`

MCPAuthorizationRuntime contains the host services used by the dynamic
registration, authorization, consent, token, and JWKS endpoints.

```go
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
```

### `MCPAuthorizationService`

MCPAuthorizationService is the production OAuth server behind the MCP flow.

```go
type MCPAuthorizationService struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MCPAuthorizationService`

### `NewMCPAuthorizationService`

NewMCPAuthorizationService validates a standalone transport-neutral server.

```go
func NewMCPAuthorizationService(input MCPAuthorizationOptions) (*MCPAuthorizationService, error)
```

## Methods on `MCPAuthorizationService`

### `AuthorizationServerMetadata`

AuthorizationServerMetadata returns the RFC 8414 document consumed by MCP
clients during protected-resource discovery.

```go
func (service *MCPAuthorizationService) AuthorizationServerMetadata(authBaseURL string) map[string]any
```

### `Descriptor`

Descriptor returns the OAuth endpoints plus the matching public JWKS route.

```go
func (service *MCPAuthorizationService) Descriptor() (engine.Plugin, error)
```

### `ResourceService`

ResourceService creates a JWT verifier sharing this server's persisted JWKS.

```go
func (service *MCPAuthorizationService) ResourceService(resource any, requiredScopes []string) (*MCPResourceService, error)
```

### `MCPAuthorizationSession`

MCPAuthorizationSession is the authenticated browser session bound to an
OAuth authorization request.

```go
type MCPAuthorizationSession struct {
	Session storage.Record
	User    storage.Record
}
```

### `MCPResourceOptions`

MCPResourceOptions configures RFC 9728 discovery and bearer-token
verification for a protected MCP resource. Resource accepts the same union
as single-auth: either one absolute resource URL or []string of URLs.

```go
type MCPResourceOptions struct {
	Resource                 any
	AuthorizationServers     []string
	ScopesSupported          []string
	ResourceMetadataMappings map[string]string
	Issuer                   string
	Audience                 any
	JWT                      jwtplugin.Options
}
```

### `MCPResourceService`

MCPResourceService is transport-neutral. Endpoints built with Guard run
unchanged through net/http, fasthttp, Fiber, and direct dispatch.

```go
type MCPResourceService struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MCPResourceService`

### `NewMCPResourceService`

NewMCPResourceService validates and snapshots a protected-resource service.

```go
func NewMCPResourceService(input MCPResourceOptions) (*MCPResourceService, error)
```

## Methods on `MCPResourceService`

### `Challenge`

Challenge returns the immutable WWW-Authenticate value used by Guard.

```go
func (service *MCPResourceService) Challenge() string
```

### `Guard`

Guard wraps one production endpoint with the same unauthorized conversion
as single-auth's mcpHandler. Verified claims are exposed through
MCPAccessTokenClaims for the application handler.

```go
func (service *MCPResourceService) Guard(next engine.HandlerFunc) engine.HandlerFunc
```

### `ProtectedResourceMetadata`

ProtectedResourceMetadata returns the RFC 9728 document exported by an MCP
resource server. The caller chooses where to mount it (normally both the
root well-known path and the path-suffixed form advertised in the challenge).

```go
func (service *MCPResourceService) ProtectedResourceMetadata() map[string]any
```

### `VerifyAccessToken`

VerifyAccessToken verifies a bearer using the configured production JWT/JWK
runtime. Missing, opaque, expired, incorrectly signed, wrong-issuer, and
wrong-audience tokens all become the same externally observable 401.

```go
func (service *MCPResourceService) VerifyAccessToken(
	ctx *engine.Context,
	token string,
) (map[string]any, error)
```

### `MetadataAdvertisedOptions`

MetadataAdvertisedOptions overrides the public scope and claim inventory
without changing the scopes accepted by the authorization server.

```go
type MetadataAdvertisedOptions struct {
	ScopesSupported []string
	ClaimsSupported []string
}
```

### `MetadataDocumentSource`

MetadataDocumentSource is implemented by MetadataService and custom
discovery providers used by exported wrapper handlers.

```go
type MetadataDocumentSource interface {
	OAuthServerMetadata(contract.Request) (map[string]any, error)
	OpenIDConfig(contract.Request) (map[string]any, error)
}
```

### `MetadataFactory`

MetadataFactory binds discovery to request-scoped base URL resolution from
the root auth runtime.

```go
type MetadataFactory struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MetadataFactory`

### `NewMetadataFactory`

NewMetadataFactory constructs the OAuth-provider metadata plugin factory.

```go
func NewMetadataFactory(options MetadataPluginOptions) *MetadataFactory
```

## Methods on `MetadataFactory`

### `Build`

```go
func (factory *MetadataFactory) Build(host singleauth.PluginHost) (engine.Plugin, error)
```

### `PluginID`

```go
func (*MetadataFactory) PluginID() string
```

### `Schema`

```go
func (*MetadataFactory) Schema() (storage.Schema, error)
```

### `Service`

Service returns the root-bound discovery service after singleauth.New.

```go
func (factory *MetadataFactory) Service() (*MetadataService, error)
```

### `MetadataJWTOptions`

MetadataJWTOptions is the discovery-facing subset of single-auth's JWT
plugin options.

```go
type MetadataJWTOptions struct {
	Issuer           string
	RemoteJWKSURL    string
	JWKSPath         string
	SigningAlgorithm string
}
```

### `MetadataOptions`

MetadataOptions contains the values that change the authorization-server
discovery document. Zero values preserve single-auth 1.6.26 defaults.

```go
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
```

### `MetadataPluginOptions`

MetadataPluginOptions configures the OAuth 2.0 and OpenID Connect discovery
surface. A nil Scopes or GrantTypes slice selects the single-auth defaults;
a non-nil empty slice is an explicit empty set.

```go
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
```

### `MetadataService`

MetadataService is the immutable production discovery runtime shared by
direct API endpoints, well-known HTTP aliases, and exported wrappers.

```go
type MetadataService struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `MetadataService`

### `NewMetadataService`

NewMetadataService validates and snapshots a standalone discovery service.

```go
func NewMetadataService(
	options MetadataPluginOptions,
	resolveBaseURL func(contract.Request) (string, error),
	skipTrailingSlashes bool,
) (*MetadataService, error)
```

## Methods on `MetadataService`

### `Descriptor`

Descriptor exposes both server-only direct API endpoints and the public
issuer-derived well-known aliases.

```go
func (service *MetadataService) Descriptor() engine.Plugin
```

### `OAuthServerMetadata`

OAuthServerMetadata returns the request-resolved OAuth or OIDC discovery
document used by getOAuthServerConfig.

```go
func (service *MetadataService) OAuthServerMetadata(request contract.Request) (map[string]any, error)
```

### `OpenIDConfig`

OpenIDConfig returns the request-resolved OIDC discovery document or the
same typed 404 emitted by single-auth when the openid scope is absent.

```go
func (service *MetadataService) OpenIDConfig(request contract.Request) (map[string]any, error)
```

### `MetadataWrapperOptions`

MetadataWrapperOptions supplies response headers to an exported discovery
wrapper.

```go
type MetadataWrapperOptions struct{ Headers contract.Headers }
```

### `OAuthOptions`

OAuthOptions exposes package-wide OAuth provider options. A nil GrantTypes
slice represents the omitted TypeScript option and keeps single-auth's
default grant set; a non-nil slice is an explicit configured set.

```go
type OAuthOptions struct {
	GrantTypes []GrantType
}
```

### `Options`

Options configures the complete native OAuth 2.1/OIDC authorization-server
plugin. It intentionally contains only server-side concepts applicable to a
Go deployment.

```go
type Options struct {
	LoginPage   string
	ConsentPage string

	Scopes         []string
	GrantTypes     []GrantType
	ValidAudiences []string

	AccessTokenExpiresIn       time.Duration
	M2MAccessTokenExpiresIn    time.Duration
	IDTokenExpiresIn           time.Duration
	RefreshTokenExpiresIn      time.Duration
	AuthorizationCodeExpiresIn time.Duration

	AllowDynamicClientRegistration         bool
	AllowUnauthenticatedClientRegistration bool
	ClientRegistrationDefaultScopes        []string
	ClientRegistrationAllowedScopes        []string
	ClientCredentialGrantDefaultScopes     []string

	DisableJWTPlugin bool
	PairwiseSecret   string

	OpaqueAccessTokenPrefix string
	RefreshTokenPrefix      string
	ClientSecretPrefix      string

	GenerateClientID          func() string
	GenerateClientSecret      func() string
	GenerateOpaqueAccessToken func() string
	GenerateRefreshToken      func() string

	CachedTrustedClients map[string]struct{}
	ClientPrivileges     ClientPrivilegeFunc
	ClientReference      ClientReferenceFunc
	RequestURIResolver   RequestURIResolver

	CustomUserInfoClaims    CustomUserInfoClaimsFunc
	CustomIDTokenClaims     CustomIDTokenClaimsFunc
	CustomAccessTokenClaims CustomAccessTokenClaimsFunc

	AdvertisedMetadata MetadataAdvertisedOptions
	Schema             storage.Schema
}
```

### `ReferenceError`

ReferenceError is the configuration error class used by the OAuth
provider package. It preserves the upstream distinction between setup
failures and request-scoped API errors.

```go
type ReferenceError struct {
	// contains filtered or unexported fields
}
```

## Methods on `ReferenceError`

### `Error`

```go
func (err *ReferenceError) Error() string
```

### `RequestURIResolver`

```go
type RequestURIResolver func(context.Context, string, string) (map[string]string, error)
```

### `RevokeAuthorizationGrant`

RevokeAuthorizationGrant is the trusted server-side result of a completed
authorization request. CreateAuthorizationCode persists it as a single-use
verification record consumed by the production /oauth2/token endpoint.

```go
type RevokeAuthorizationGrant struct {
	ClientID            string
	UserID              string
	SessionID           string
	RedirectURI         string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ReferenceID         string
	AuthTime            time.Time
}
```

### `RevokeClientSecretVerifier`

RevokeClientSecretVerifier compares a presented client secret to its stored
representation. The default verifies single-auth's SHA-256 hash format.

```go
type RevokeClientSecretVerifier func(context.Context, string, string) (bool, error)
```

### `RevokeInput`

RevokeInput is the server-side and direct-API input for oauth2Revoke.

```go
type RevokeInput struct {
	ClientID      string          `json:"client_id"`
	ClientSecret  string          `json:"client_secret"`
	Token         string          `json:"token"`
	TokenTypeHint RevokeTokenType `json:"token_type_hint"`
}
```

### `RevokeIssuer`

```go
type RevokeIssuer struct {
	// contains filtered or unexported fields
}
```

### `RevokeIssuerOptions`

RevokeIssuerOptions enables the production token endpoint used with the
revocation service. It deliberately shares storage, hashing, prefixes, and
JWT/JWKS options with RevokeService so an issued token is always consumable
by oauth2Revoke without test-only glue.

```go
type RevokeIssuerOptions struct {
	Random                        io.Reader
	AccessTokenExpiresIn          time.Duration
	M2MAccessTokenExpiresIn       time.Duration
	IDTokenExpiresIn              time.Duration
	RefreshTokenExpiresIn         time.Duration
	AuthorizationCodeExpiresIn    time.Duration
	ValidAudiences                []string
	ServerScopes                  []string
	ClientCredentialDefaultScopes []string
	GenerateOpaqueAccessToken     func() string
	GenerateRefreshToken          func() string
	SignJWT                       func(*engine.Context, map[string]any) (string, error)
	SignIDToken                   func(*engine.Context, storage.Record, storage.Record, []string, string, string, time.Time) (string, error)
	ResolveSubject                func(context.Context, string, storage.Record) (string, error)
	CustomAccessTokenClaims       CustomAccessTokenClaimsFunc
	CustomIDTokenClaims           CustomIDTokenClaimsFunc
}
```

### `RevokeJWTDisposition`

RevokeJWTDisposition tells the revocation service whether a presented value
is a valid stateless access token, an inactive JWT that RFC 7009 may accept,
or a non-JWT value that must be looked up as an opaque access token.

```go
type RevokeJWTDisposition uint8
```

## Constants associated with `RevokeJWTDisposition`

```go
const (
	RevokeJWTNotJWT RevokeJWTDisposition = iota
	RevokeJWTValid
	RevokeJWTInactive
)
```

### `RevokeJWTValidator`

RevokeJWTValidator performs the configured JWT plugin's signature and claim
validation. Only malformed compact JWS values return RevokeJWTNotJWT so
opaque lookup can continue. Expired or structurally invalid JWT claim sets
return RevokeJWTInactive; signature and issuer/audience failures are errors.

```go
type RevokeJWTValidator func(*engine.Context, string) (RevokeJWTDisposition, error)
```

### `RevokeOptions`

RevokeOptions mirrors the OAuth provider configuration that affects token
revocation. Prefixes are presentation-only and are removed before custom
decoding or storage hashing.

```go
type RevokeOptions struct {
	OpaqueAccessTokenPrefix string
	RefreshTokenPrefix      string
	ClientSecretPrefix      string
	// JWT binds the same signing/JWKS configuration used by the JWT plugin.
	// When supplied, NewRevokeService installs a real stored-JWK validator if
	// Runtime.ValidateJWT was not explicitly overridden.
	JWT     *jwtplugin.Options
	Issuer  *RevokeIssuerOptions
	Runtime RevokeRuntime
}
```

### `RevokeRefreshTokenDecoder`

RevokeRefreshTokenDecoder unwraps a custom formatted refresh token after its
configured prefix has been removed.

```go
type RevokeRefreshTokenDecoder func(context.Context, string) (string, error)
```

### `RevokeRuntime`

RevokeRuntime supplies persistence and cryptographic services to the
transport-neutral endpoint.

```go
type RevokeRuntime struct {
	Adapter            storage.Adapter
	AdapterForContext  func(context.Context) storage.TransactionAdapter
	Clock              func() time.Time
	ValidateJWT        RevokeJWTValidator
	StoredToken        RevokeStoredToken
	DecodeRefreshToken RevokeRefreshTokenDecoder
	VerifyClientSecret RevokeClientSecretVerifier
}
```

### `RevokeService`

RevokeService owns the OAuth provider's RFC 7009 revocation behavioral compatibility.

```go
type RevokeService struct {
	// contains filtered or unexported fields
}
```

## Constructors and functions for `RevokeService`

### `NewRevokeService`

NewRevokeService validates and snapshots a production revocation service.

```go
func NewRevokeService(input RevokeOptions) (*RevokeService, error)
```

## Methods on `RevokeService`

### `CreateAuthorizationCode`

CreateAuthorizationCode stores a random, hashed, single-use code for the
authorization_code grant. This is the trusted binding an authorize endpoint
calls after user/session/consent checks have completed.

```go
func (service *RevokeService) CreateAuthorizationCode(
	ctx context.Context,
	input RevokeAuthorizationGrant,
) (string, error)
```

### `Descriptor`

Descriptor returns the isolated OAuth revoke plugin surface.

```go
func (service *RevokeService) Descriptor() engine.Plugin
```

### `Revoke`

Revoke validates client authentication and revokes the supplied token. A
successful RFC 7009 response is JSON null, exactly as in single-auth 1.6.26.

```go
func (service *RevokeService) Revoke(
	ctx *engine.Context,
	input RevokeInput,
) (contract.Response, error)
```

### `RevokeStoredToken`

RevokeStoredToken resolves the database representation of an externally
presented access or refresh token. single-auth's default is SHA-256 encoded
with unpadded base64url; custom storeTokens implementations bind here.

```go
type RevokeStoredToken func(context.Context, string, RevokeTokenType) (string, error)
```

### `RevokeTokenType`

RevokeTokenType identifies the two token families accepted by RFC 7009.

```go
type RevokeTokenType string
```

## Constants associated with `RevokeTokenType`

```go
const (
	RevokeAccessToken       RevokeTokenType = "access_token"
	RevokeRefreshToken      RevokeTokenType = "refresh_token"
	RevokeAuthorizationCode RevokeTokenType = "authorization_code"
)
```

### `Server`

Server is the complete transport-neutral OAuth/OIDC implementation.

```go
type Server struct {
	// contains filtered or unexported fields
}
```

### `Session`

Session is the authenticated root session exposed to server callbacks.

```go
type Session struct {
	Session storage.Record
	User    storage.Record
}
```

### `TokenEndpointAuthMethod`

TokenEndpointAuthMethod includes confidential-client authentication and
the public-client "none" method. The alias preserves assignment from an
AuthMethod just as single-auth's TypeScript union does.

```go
type TokenEndpointAuthMethod = AuthMethod
```

## Constants associated with `TokenEndpointAuthMethod`

```go
const TokenEndpointAuthMethodNone TokenEndpointAuthMethod = "none"
```

### `UpdateConsentInput`

UpdateConsentInput is the only mutation accepted by the public update
endpoint in single-auth 1.6.26.

```go
type UpdateConsentInput struct {
	ID     string
	UserID string
	Scopes []string
}
```

### `UserInfoCustomClaims`

UserInfoCustomClaims adds application claims after the normal OIDC claims
have been selected. Custom values intentionally override normal values.

```go
type UserInfoCustomClaims func(
	context.Context,
	storage.Record,
	[]string,
	map[string]any,
) (map[string]any, error)
```

### `UserInfoJWTValidator`

UserInfoJWTValidator verifies a JWT access token and returns its RFC 7662
claims. It must return ErrInvalidJWTAccessToken when the input is not a JWT
issued by this provider.

```go
type UserInfoJWTValidator func(*engine.Context, string) (map[string]any, error)
```

### `UserInfoOptions`

UserInfoOptions configures single-auth's OIDC /userinfo endpoint.

```go
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
```

### `UserInfoSubjectResolver`

UserInfoSubjectResolver implements pairwise subject identifiers. The client
ID comes from client_id or azp on the validated access-token claims.

```go
type UserInfoSubjectResolver func(
	context.Context,
	string,
	string,
) (string, error)
```

