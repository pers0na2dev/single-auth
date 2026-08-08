---
title: "github.com/pers0na2dev/single-auth/plugins/genericoauth"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/genericoauth.

- Import path: `github.com/pers0na2dev/single-auth/plugins/genericoauth`
- Package name: `genericoauth`

Package genericoauth ports single-auth 1.6.26's generic-oauth plugin.

It exposes the dedicated OAuth2 sign-in, callback and account-link routes,
registers each configured provider with the root account/token runtime, and
ships the upstream provider helpers.

## Constants

```go
const (
	ErrorInvalidOAuthConfiguration = "INVALID_OAUTH_CONFIGURATION"
	ErrorTokenURLNotFound          = "TOKEN_URL_NOT_FOUND"
	ErrorProviderConfigNotFound    = "PROVIDER_CONFIG_NOT_FOUND"
	ErrorProviderIDRequired        = "PROVIDER_ID_REQUIRED"
	ErrorInvalidOAuthConfig        = "INVALID_OAUTH_CONFIG"
	ErrorSessionRequired           = "SESSION_REQUIRED"
	ErrorIssuerMismatch            = "ISSUER_MISMATCH"
	ErrorIssuerMissing             = "ISSUER_MISSING"
)
```

```go
const Version = "1.6.26"
```

## Variables

```go
var ErrorMessages = map[string]string{
	ErrorInvalidOAuthConfiguration: "Invalid OAuth configuration",
	ErrorTokenURLNotFound:          "Invalid OAuth configuration. Token URL not found.",
	ErrorProviderConfigNotFound:    "No config found for provider",
	ErrorProviderIDRequired:        "Provider ID is required",
	ErrorInvalidOAuthConfig:        "Invalid OAuth configuration.",
	ErrorSessionRequired:           "Session is required",
	ErrorIssuerMismatch:            "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
	ErrorIssuerMissing:             "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
}
```

## Functions

### `MustNew`

```go
func MustNew(options Options) engine.Plugin
```

### `New`

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `ProviderCallbackURL`

ProviderCallbackURL returns the default callback URI used by helper-based
generic providers. It is exported for configuration diagnostics.

```go
func ProviderCallbackURL(baseURL, providerID string) (string, error)
```

## Types

### `Auth0Options`

```go
type Auth0Options struct {
	BaseOAuthProviderOptions
	Domain string
}
```

### `BaseOAuthProviderOptions`

BaseOAuthProviderOptions is the shared option set accepted by the provider
helpers. ClientSecret is required by the upstream helpers and is retained as
a concrete string in Go.

```go
type BaseOAuthProviderOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool

	DisableImplicitSignUp bool
	DisableSignUp         bool
	OverrideUserInfo      bool
	HTTPClient            *http.Client
}
```

### `Config`

Config mirrors single-auth 1.6.26 GenericOAuthConfig. AccessTokenExpiresIn
is a Go duration; zero preserves an unknown expiry when the provider omits
expires_in.

```go
type Config struct {
	ProviderID string

	DiscoveryURL            string
	Issuer                  string
	RequireIssuerValidation bool
	AuthorizationURL        string
	TokenURL                string
	UserInfoURL             string
	ClientID                string
	ClientSecret            string
	Scopes                  []string
	RedirectURI             string
	ResponseType            string
	ResponseMode            string
	Prompt                  string
	PKCE                    bool
	AccessType              string
	AccessTokenExpiresIn    time.Duration

	GetToken         GetTokenFunc
	GetUserInfo      GetUserInfoFunc
	MapProfileToUser MapProfileToUserFunc

	AuthorizationURLParams ParamSource
	TokenURLParams         ParamSource

	DisableImplicitSignUp bool
	DisableSignUp         bool
	Authentication        oauth2.Authentication
	DiscoveryHeaders      map[string]string
	AuthorizationHeaders  map[string]string
	OverrideUserInfo      bool
	HTTPClient            *http.Client
}
```

## Constructors and functions for `Config`

### `Auth0`

```go
func Auth0(options Auth0Options) Config
```

### `Gumroad`

```go
func Gumroad(options GumroadOptions) Config
```

### `HubSpot`

```go
func HubSpot(options HubSpotOptions) Config
```

### `Keycloak`

```go
func Keycloak(options KeycloakOptions) Config
```

### `Line`

```go
func Line(options LineOptions) Config
```

### `MicrosoftEntraID`

```go
func MicrosoftEntraID(options MicrosoftEntraIDOptions) Config
```

### `Okta`

```go
func Okta(options OktaOptions) Config
```

### `Patreon`

```go
func Patreon(options PatreonOptions) Config
```

### `Slack`

```go
func Slack(options SlackOptions) Config
```

### `Yandex`

```go
func Yandex(options YandexOptions) Config
```

### `EndpointParamsFunc`

```go
type EndpointParamsFunc func(*engine.Context) map[string]string
```

### `GetTokenFunc`

```go
type GetTokenFunc func(context.Context, TokenRequest) (oauth2.Tokens, error)
```

### `GetUserInfoFunc`

```go
type GetUserInfoFunc func(context.Context, oauth2.Tokens) (Profile, error)
```

### `GumroadOptions`

```go
type GumroadOptions struct{ BaseOAuthProviderOptions }
```

### `HubSpotOptions`

```go
type HubSpotOptions struct{ BaseOAuthProviderOptions }
```

### `KeycloakOptions`

```go
type KeycloakOptions struct {
	BaseOAuthProviderOptions
	Issuer string
}
```

### `LineOptions`

```go
type LineOptions struct {
	BaseOAuthProviderOptions
	ProviderID string
}
```

### `LinkInput`

LinkInput is the direct API equivalent of POST /oauth2/link.

```go
type LinkInput struct {
	ProviderID       string
	CallbackURL      string
	Scopes           []string
	ErrorCallbackURL string
}
```

### `MapProfileToUserFunc`

```go
type MapProfileToUserFunc func(context.Context, Profile) (Profile, error)
```

### `MicrosoftEntraIDOptions`

```go
type MicrosoftEntraIDOptions struct {
	BaseOAuthProviderOptions
	TenantID string
}
```

### `OktaOptions`

```go
type OktaOptions struct {
	BaseOAuthProviderOptions
	Issuer string
}
```

### `Options`

```go
type Options struct {
	Config  []Config
	Runtime Runtime
}
```

### `ParamSource`

ParamSource accepts either static endpoint parameters or a request-scoped
resolver. When both are set, Resolve takes precedence, like single-auth's
record-or-function option.

```go
type ParamSource struct {
	Static  map[string]string
	Resolve EndpointParamsFunc
}
```

### `PatreonOptions`

```go
type PatreonOptions struct{ BaseOAuthProviderOptions }
```

### `Profile`

Profile is the lossless JSON object returned by a generic OAuth user-info
endpoint. Numeric account IDs remain numeric until the final normalization
step, matching single-auth's string | number input contract.

```go
type Profile map[string]any
```

### `Runtime`

Runtime is the transport-neutral host surface required by the standalone
plugin. NewFactory binds it to singleauth.Auth.

```go
type Runtime struct {
	BaseURL              string
	BasePath             string
	ErrorURL             string
	StateStrategy        string
	Secret               string
	SkipStateCookieCheck bool
	AllowDifferentEmails bool

	Clock      func() time.Time
	Random     io.Reader
	HTTPClient *http.Client
	Logger     *logger.Logger

	ResolveBaseURL func(contract.Request) (string, error)
	Cookie         func(contract.Request, string, string) (string, cookies.Options)
	DecryptSecret  func(string) ([]byte, error)

	CreateOAuthState func(*engine.Context, singleauth.PluginOAuthStateInput) (singleauth.PluginOAuthState, error)
	HandleOAuthUser  func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	LinkOAuthAccount func(*engine.Context, string, *providers.Provider, oauth2.UserInfo, oauth2.Tokens) error
	ResolveSession   func(*engine.Context, singleauth.PluginSessionMode) (*singleauth.PluginSessionState, error)
	RefreshSession   func(*engine.Context, singleauth.PluginSessionState, bool) error

	FindVerification    func(context.Context, string) (storage.Record, error)
	ConsumeVerification func(context.Context, string) (storage.Record, error)
}
```

### `SignInInput`

SignInInput is the direct API equivalent of POST /sign-in/oauth2.

```go
type SignInInput struct {
	ProviderID         string
	CallbackURL        string
	ErrorCallbackURL   string
	NewUserCallbackURL string
	DisableRedirect    bool
	Scopes             []string
	RequestSignUp      *bool
	AdditionalData     map[string]any
}
```

### `SlackOptions`

```go
type SlackOptions struct{ BaseOAuthProviderOptions }
```

### `TokenRequest`

TokenRequest is supplied to a provider-specific authorization-code
exchange. CodeVerifier is empty when PKCE is disabled.

```go
type TokenRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}
```

### `YandexOptions`

```go
type YandexOptions struct{ BaseOAuthProviderOptions }
```

