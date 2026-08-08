---
title: "github.com/pers0na2dev/single-auth/plugins/oidcprovider"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/oidcprovider.

- Import path: `github.com/pers0na2dev/single-auth/plugins/oidcprovider`
- Package name: `oidcprovider`

Package oidcprovider implements the frozen single-auth 1.6.26
oidc-provider plugin. The package name deliberately omits the dash used by
the TypeScript plugin ID so it can be imported as ordinary Go.

## Constants

```go
const (
	PluginID = "oidc-provider"
	Version  = "1.6.26"

	DiscoveryPath    = "/.well-known/openid-configuration"
	AuthorizePath    = "/oauth2/authorize"
	ConsentPath      = "/oauth2/consent"
	TokenPath        = "/oauth2/token"
	UserInfoPath     = "/oauth2/userinfo"
	RegistrationPath = "/oauth2/register"
	ClientPath       = "/oauth2/client/:id"
	EndSessionPath   = "/oauth2/endsession"
)
```

## Functions

### `MustNew`

MustNew constructs a descriptor or panics.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New constructs a transport-neutral plugin descriptor.

```go
func New(input Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds OIDC to root storage, sessions, cookies, verification
storage, secret rotation, trusted-origin checks, and the optional JWT plugin.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

### `ProviderMetadata`

ProviderMetadata returns the frozen OpenID Provider discovery document.
Override entries are applied last, exactly like the TypeScript object spread.

```go
func ProviderMetadata(issuer, authBaseURL string, useJWTPlugin bool, override map[string]any) (map[string]any, error)
```

### `Schema`

Schema returns a fresh copy of the frozen OIDC provider's three models.

```go
func Schema() storage.Schema
```

## Types

### `AccessToken`

AccessToken is the normalized oauthAccessToken record.

```go
type AccessToken struct {
	ID                    any
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	ClientID              string
	UserID                string
	Scopes                string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
```

### `AdditionalUserInfoClaimFunc`

AdditionalUserInfoClaimFunc adds claims to userinfo and ID-token payloads.
Returned entries override built-in claims, matching object-spread order in
single-auth 1.6.26.

```go
type AdditionalUserInfoClaimFunc func(
	context.Context,
	storage.Record,
	[]string,
	Client,
) (map[string]any, error)
```

### `AuthorizationCodeValue`

AuthorizationCodeValue is the persisted authorization/consent state.

```go
type AuthorizationCodeValue struct {
	ClientID            string   `json:"clientId"`
	RedirectURI         string   `json:"redirectURI"`
	Scope               []string `json:"scope"`
	UserID              string   `json:"userId"`
	AuthTime            int64    `json:"authTime"`
	RequireConsent      bool     `json:"requireConsent"`
	State               *string  `json:"state"`
	CodeChallenge       string   `json:"codeChallenge,omitempty"`
	CodeChallengeMethod string   `json:"codeChallengeMethod,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
}
```

### `BaseURLResolver`

```go
type BaseURLResolver func(contract.Request) (string, error)
```

### `Client`

Client is the normalized oauthApplication record accepted by trusted-client
configuration and returned by client lookup.

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
	SkipConsent          bool
}
```

### `ClientSecretCryptFunc`

ClientSecretCryptFunc is used for custom reversible client-secret storage.

```go
type ClientSecretCryptFunc func(context.Context, string) (string, error)
```

### `ClientSecretHashFunc`

ClientSecretHashFunc is used for custom one-way client-secret storage.

```go
type ClientSecretHashFunc func(context.Context, string) (string, error)
```

### `ClientSecretStorageMode`

ClientSecretStorageMode controls how dynamically registered client secrets
are persisted. The plaintext secret is always returned once to the client.

```go
type ClientSecretStorageMode string
```

## Constants associated with `ClientSecretStorageMode`

```go
const (
	ClientSecretPlain            ClientSecretStorageMode = "plain"
	ClientSecretHashed           ClientSecretStorageMode = "hashed"
	ClientSecretEncrypted        ClientSecretStorageMode = "encrypted"
	ClientSecretCustomHash       ClientSecretStorageMode = "custom-hash"
	ClientSecretCustomEncryption ClientSecretStorageMode = "custom-encryption"
)
```

### `ConsentHTMLFunc`

ConsentHTMLFunc renders the inline consent document.

```go
type ConsentHTMLFunc func(context.Context, ConsentHTMLInput) (string, error)
```

### `ConsentHTMLInput`

ConsentHTMLInput is passed to GetConsentHTML when no external consent page
is configured.

```go
type ConsentHTMLInput struct {
	ClientID       string
	ClientName     string
	ClientIcon     *string
	ClientMetadata map[string]any
	Code           string
	Scopes         []string
}
```

### `ContextAdapterResolver`

```go
type ContextAdapterResolver func(context.Context) storage.TransactionAdapter
```

### `DeleteSessionFunc`

```go
type DeleteSessionFunc func(context.Context, string) error
```

### `FindSessionFunc`

```go
type FindSessionFunc func(context.Context, string) (*SessionState, error)
```

### `JWTPluginSignFunc`

```go
type JWTPluginSignFunc func(*engine.Context, map[string]any, string, string, int64) (string, error)
```

### `JWTPluginVerifyFunc`

```go
type JWTPluginVerifyFunc func(*engine.Context, string, string) (map[string]any, error)
```

### `NewSessionFunc`

```go
type NewSessionFunc func(*engine.Context) *SessionState
```

### `OAuthErrorBody`

OAuthErrorBody is the RFC-compatible error representation.

```go
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
```

### `Options`

Options configures the deprecated single-auth OIDC provider. Zero token and
code durations select the frozen upstream defaults. RequirePKCE deliberately
remains false by default because that is the actual 1.6.26 implementation,
despite the historical TypeScript documentation saying otherwise.

```go
type Options struct {
	AccessTokenExpiresIn           time.Duration
	AllowDynamicClientRegistration bool
	Metadata                       map[string]any
	RefreshTokenExpiresIn          time.Duration
	CodeExpiresIn                  time.Duration
	Scopes                         []string
	DefaultScope                   string
	ConsentPage                    string
	GetConsentHTML                 ConsentHTMLFunc
	LoginPage                      string
	RequirePKCE                    bool
	AllowPlainCodeChallengeMethod  bool
	GenerateClientID               func() string
	GenerateClientSecret           func() string
	GetAdditionalUserInfoClaim     AdditionalUserInfoClaimFunc
	TrustedClients                 []Client
	StoreClientSecret              ClientSecretStorageMode
	HashClientSecret               ClientSecretHashFunc
	EncryptClientSecret            ClientSecretCryptFunc
	DecryptClientSecret            ClientSecretCryptFunc
	UseJWTPlugin                   bool
	Schema                         storage.Schema
	Runtime                        Runtime
}
```

## Constructors and functions for `Options`

### `NormalizeOptions`

NormalizeOptions applies the frozen defaults and snapshots mutable option
values without requiring runtime dependencies.

```go
func NormalizeOptions(input Options) (Options, error)
```

### `Prompt`

Prompt is one recognized OpenID Connect prompt value.

```go
type Prompt string
```

## Constants associated with `Prompt`

```go
const (
	PromptLogin         Prompt = "login"
	PromptConsent       Prompt = "consent"
	PromptSelectAccount Prompt = "select_account"
	PromptNone          Prompt = "none"
)
```

### `PromptSet`

PromptSet is the deduplicated result of ParsePrompt.

```go
type PromptSet map[Prompt]struct{}
```

## Constructors and functions for `PromptSet`

### `ParsePrompt`

ParsePrompt implements the exact frozen parser: recognized values are
deduplicated, unknown values are ignored, and none cannot be combined with
another recognized prompt.

```go
func ParsePrompt(value string) (PromptSet, error)
```

## Methods on `PromptSet`

### `Has`

Has reports whether prompt is present.

```go
func (set PromptSet) Has(prompt Prompt) bool
```

### `ResolveSessionFunc`

```go
type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
```

### `Runtime`

Runtime contains dependencies injected by NewFactory. Explicit runtime
values also make New useful in focused engine tests.

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
	DeleteSession       DeleteSessionFunc
	IsTrustedOrigin     TrustedOriginFunc
	CreateVerification  VerificationCreateFunc
	FindVerification    VerificationReadFunc
	PeekVerification    VerificationReadFunc
	ConsumeVerification VerificationReadFunc
	UpdateVerification  VerificationUpdateFunc
	DeleteVerification  VerificationDeleteFunc
	EncryptSecret       func([]byte) (string, error)
	DecryptSecret       func(string) ([]byte, error)
	SignWithJWTPlugin   JWTPluginSignFunc
	VerifyWithJWTPlugin JWTPluginVerifyFunc
}
```

### `SessionCookieResolver`

```go
type SessionCookieResolver func(contract.Request) (string, cookies.Options)
```

### `SessionState`

SessionState is the root session/user pair visible to authorization and
logout handlers.

```go
type SessionState struct {
	Session storage.Record
	User    storage.Record
}
```

### `TrustedOriginFunc`

```go
type TrustedOriginFunc func(contract.Request, string, bool) (bool, error)
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

