---
title: "github.com/pers0na2dev/single-auth/plugins/mcp"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/mcp.

- Import path: `github.com/pers0na2dev/single-auth/plugins/mcp`
- Package name: `mcp`

Package mcp implements the single-auth 1.6.26 MCP OAuth authorization
server plugin.

The server surface is transport neutral and therefore works through the
root net/http handler as well as the fasthttp and Fiber adapters.

## Constants

```go
const (
	PluginID = "mcp"
	Version  = "1.6.26"

	DiscoveryPath         = "/.well-known/oauth-authorization-server"
	ProtectedResourcePath = "/.well-known/oauth-protected-resource"
	AuthorizePath         = "/mcp/authorize"
	TokenPath             = "/mcp/token"
	RegisterPath          = "/mcp/register"
	SessionPath           = "/mcp/get-session"
	ConsentPath           = "/oauth2/consent"
)
```

## Functions

### `MustNew`

MustNew constructs a descriptor or panics.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a transport-neutral MCP descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds MCP to the final root adapter, session implementation,
verification storage (including secondary storage), cookie configuration,
random source, and dynamic base URL resolver.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `OAuthDiscoveryMetadataHandler`

OAuthDiscoveryMetadataHandler exposes discovery metadata with the CORS
headers used by single-auth's oAuthDiscoveryMetadata helper.

```go
func OAuthDiscoveryMetadataHandler(auth *singleauth.Auth) http.Handler
```

### `OAuthProtectedResourceMetadataHandler`

OAuthProtectedResourceMetadataHandler exposes protected-resource metadata
with the CORS headers used by single-auth's helper.

```go
func OAuthProtectedResourceMetadataHandler(auth *singleauth.Auth) http.Handler
```

### `ProtectedResourceMetadata`

ProtectedResourceMetadata returns RFC 9728 metadata for the protected MCP
resource.

```go
func ProtectedResourceMetadata(authBaseURL, resource string, oidcMetadata map[string]any) (map[string]any, error)
```

### `ProviderMetadata`

ProviderMetadata returns the OAuth/OIDC discovery document advertised by
single-auth's MCP plugin. Override entries are applied last.

```go
func ProviderMetadata(issuer, authBaseURL string, override map[string]any) (map[string]any, error)
```

### `Schema`

Schema returns a fresh copy of the three models inherited by MCP from the
frozen single-auth OIDC provider.

```go
func Schema() storage.Schema
```

### `WithMCPAuth`

WithMCPAuth protects a net/http resource handler with getMcpSession and
emits the MCP JSON-RPC authentication challenge used by single-auth.

```go
func WithMCPAuth(
	auth *singleauth.Auth,
	handler func(http.ResponseWriter, *http.Request, AccessToken),
) http.Handler
```

## Types

### `AccessToken`

AccessToken is the oauthAccessToken representation returned by
getMcpSession and used by resource-server middleware.

```go
type AccessToken struct {
	ID                    any       `json:"id,omitempty"`
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
	ClientID              string    `json:"clientId"`
	UserID                string    `json:"userId"`
	Scopes                string    `json:"scopes"`
	CreatedAt             time.Time `json:"createdAt,omitempty"`
	UpdatedAt             time.Time `json:"updatedAt,omitempty"`
}
```

### `AdditionalUserInfoClaimFunc`

AdditionalUserInfoClaimFunc adds claims to an ID token. Returned claims
take precedence over the built-in profile and email claims, matching the
object-spread order in single-auth 1.6.26.

```go
type AdditionalUserInfoClaimFunc func(
	context.Context,
	storage.Record,
	[]string,
	Client,
) (map[string]any, error)
```

### `BaseURLResolver`

```go
type BaseURLResolver func(contract.Request) (string, error)
```

### `Client`

Client is the normalized oauthApplication model used by authorization and
token endpoints.

```go
type Client struct {
	ID                   any
	ClientID             string
	ClientSecret         string
	Type                 string
	Name                 string
	Icon                 *string
	Metadata             map[string]any
	Disabled             bool
	RedirectURLs         []string
	UserID               *string
	AuthenticationScheme string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}
```

### `ContextAdapterResolver`

```go
type ContextAdapterResolver func(context.Context) storage.TransactionAdapter
```

### `FindSessionFunc`

```go
type FindSessionFunc func(context.Context, string) (*SessionState, error)
```

### `NewSessionFunc`

```go
type NewSessionFunc func(*engine.Context) *SessionState
```

### `OAuthErrorBody`

OAuthErrorBody is the wire representation used by the token and consent
endpoints while the direct API retains a typed APIError.

```go
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
```

### `OIDCOptions`

OIDCOptions is the MCP plugin's embedded OIDC-provider configuration.
Zero durations select single-auth's defaults.

```go
type OIDCOptions struct {
	AccessTokenExpiresIn          time.Duration
	RefreshTokenExpiresIn         time.Duration
	CodeExpiresIn                 time.Duration
	Scopes                        []string
	DefaultScope                  string
	ConsentPage                   string
	RequirePKCE                   bool
	AllowPlainCodeChallengeMethod bool
	GenerateClientID              func() string
	GenerateClientSecret          func() string
	GetAdditionalUserInfoClaim    AdditionalUserInfoClaimFunc
	Metadata                      map[string]any
}
```

### `Options`

Options configures the MCP OAuth server.

```go
type Options struct {
	LoginPage  string
	Resource   string
	OIDCConfig OIDCOptions
	Schema     storage.Schema
	Runtime    Runtime
}
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
```

### `Runtime`

Runtime contains dependencies injected by NewFactory. It remains public so
the transport-neutral descriptor can also be embedded without the root
Auth constructor in focused protocol tests.

```go
type Runtime struct {
	Adapter             storage.Adapter
	AdapterForContext   ContextAdapterResolver
	Clock               func() time.Time
	Random              io.Reader
	Secret              string
	Issuer              string
	BasePath            string
	ResolveBaseURL      BaseURLResolver
	ResolveSession      ResolveSessionFunc
	SessionCookie       SessionCookieResolver
	FindSession         FindSessionFunc
	NewSession          NewSessionFunc
	CreateVerification  VerificationCreateFunc
	FindVerification    VerificationReadFunc
	PeekVerification    VerificationReadFunc
	ConsumeVerification VerificationReadFunc
	UpdateVerification  VerificationUpdateFunc
	DeleteVerification  VerificationDeleteFunc
}
```

### `SessionCookieResolver`

```go
type SessionCookieResolver func(contract.Request) (string, cookies.Options)
```

### `SessionState`

SessionState is the root session/user pair visible during authorization.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `VerificationCreateFunc`

```go
type VerificationCreateFunc func(context.Context, string, string, time.Time) (storage.Record, error)
```

### `VerificationDeleteFunc`

```go
type VerificationDeleteFunc func(context.Context, string) error
```

### `VerificationReadFunc`

```go
type VerificationReadFunc func(context.Context, string) (storage.Record, error)
```

### `VerificationUpdateFunc`

```go
type VerificationUpdateFunc func(context.Context, string, storage.Record) error
```

