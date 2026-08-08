---
title: "github.com/pers0na2dev/single-auth/plugins/sso"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/plugins/sso.

- Import path: `github.com/pers0na2dev/single-auth/plugins/sso`
- Package name: `sso`

Package sso implements single-auth's SSO plugin endpoints on top of the
transport-independent SAML protocol package.

## Constants

```go
const (
	EndpointRegisterSSO        = "registerSSOProvider"
	EndpointListSSO            = "listSSOProviders"
	EndpointGetSSO             = "getSSOProvider"
	EndpointUpdateSSO          = "updateSSOProvider"
	EndpointDeleteSSO          = "deleteSSOProvider"
	EndpointRequestDomain      = "requestDomainVerification"
	EndpointVerifyDomain       = "verifyDomain"
	EndpointSignInSSO          = "signInSSO"
	EndpointOIDCCallback       = "handleSSOCallback"
	EndpointOIDCSharedCallback = "handleSSOCallbackShared"
	EndpointSAMLCallback       = "handleSAMLCallback"
	EndpointSAMLACS            = "handleSAMLAssertionConsumerService"
	EndpointSPMetadata         = "spMetadata"
	EndpointSLO                = "sloEndpoint"
	EndpointInitiateSLO        = "initiateSLO"
)
```

```go
const Version = "1.6.26"
```

## Functions

### `AssignOrganizationByDomain`

AssignOrganizationByDomain assigns a user to the organization attached to
the first matching SSO provider, with the same verification and membership
guards as single-auth 1.6.26.

```go
func AssignOrganizationByDomain(
	ctx context.Context,
	runtime OrganizationAssignmentContext,
	options AssignOrganizationByDomainOptions,
) error
```

### `AssignOrganizationFromProvider`

AssignOrganizationFromProvider creates the provider-linked organization
membership once. It is transport-neutral and deliberately idempotent.

```go
func AssignOrganizationFromProvider(
	ctx context.Context,
	runtime OrganizationAssignmentContext,
	options AssignOrganizationFromProviderOptions,
) error
```

### `ComputeDiscoveryURL`

ComputeDiscoveryURL returns the OIDC discovery location used by Better
Auth, including the issuer-path behavioral compatibility and trailing-slash normalization.

```go
func ComputeDiscoveryURL(issuer string) string
```

### `MustNew`

MustNew is New with panic-on-configuration-error semantics.

```go
func MustNew(options Options) engine.Plugin
```

### `New`

New validates and snapshots a transport-neutral SSO plugin.

```go
func New(options Options) (engine.Plugin, error)
```

### `NewFactory`

NewFactory binds SSO state and AuthnRequest correlation to the root Better
Auth verification store.

```go
func NewFactory(options Options) singleauth.PluginFactory
```

## Types

### `AssignOrganizationByDomainOptions`

AssignOrganizationByDomainOptions mirrors single-auth's domain assignment
options for non-SSO sign-in methods.

```go
type AssignOrganizationByDomainOptions struct {
	User                      OrganizationAssignmentUser
	Provisioning              OrganizationProvisioningOptions
	DomainVerificationEnabled bool
}
```

### `AssignOrganizationFromProviderOptions`

AssignOrganizationFromProviderOptions provisions membership from the SSO
provider that has already completed an OIDC or SAML identity flow.

```go
type AssignOrganizationFromProviderOptions struct {
	User         OrganizationAssignmentUser
	UserInfo     storage.Record
	Provider     storage.Record
	Tokens       *oauth2.Tokens
	Provisioning OrganizationProvisioningOptions
}
```

### `DefaultProvider`

DefaultProvider is an application-configured SSO provider. It takes
precedence over database providers, matching single-auth's defaultSSO
option.

```go
type DefaultProvider struct {
	ProviderID string
	Domain     string
	SAMLConfig SAMLConfig
	OIDCConfig *OIDCConfig
}
```

### `DomainVerificationOptions`

DomainVerificationOptions controls whether persisted SSO providers carry
the verification marker used by domain-based organization assignment.

```go
type DomainVerificationOptions struct {
	Enabled     bool
	TokenPrefix string
	LookupTXT   func(context.Context, string) ([]string, error)
}
```

### `OIDCConfig`

OIDCConfig is the persisted and application-configured SSO OIDC provider
contract. PKCE defaults to enabled when omitted.

```go
type OIDCConfig struct {
	Issuer                      string      `json:"issuer"`
	ClientID                    string      `json:"clientId"`
	ClientSecret                string      `json:"clientSecret"`
	AuthorizationEndpoint       string      `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint               string      `json:"tokenEndpoint,omitempty"`
	UserInfoEndpoint            string      `json:"userInfoEndpoint,omitempty"`
	JWKSEndpoint                string      `json:"jwksEndpoint,omitempty"`
	DiscoveryEndpoint           string      `json:"discoveryEndpoint,omitempty"`
	TokenEndpointAuthentication string      `json:"tokenEndpointAuthentication,omitempty"`
	Scopes                      []string    `json:"scopes,omitempty"`
	ScopesSupported             []string    `json:"scopesSupported,omitempty"`
	PKCE                        *bool       `json:"pkce,omitempty"`
	Mapping                     OIDCMapping `json:"mapping,omitempty"`
	OverrideUserInfo            bool        `json:"overrideUserInfo,omitempty"`
	SkipDiscovery               bool        `json:"skipDiscovery,omitempty"`
}
```

### `OIDCMapping`

OIDCMapping maps OIDC claims onto single-auth's normalized OAuth user
shape. Empty fields use sub, email, email_verified, name, and picture.

```go
type OIDCMapping struct {
	ID            string            `json:"id,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Image         string            `json:"image,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}
```

### `OIDCRuntimeOptions`

OIDCRuntimeOptions controls outbound discovery, token, UserInfo, and JWKS
requests. LookupIP is injectable for deterministic SSRF/DNS-rebinding tests.

```go
type OIDCRuntimeOptions struct {
	HTTPClient       *http.Client
	DiscoveryTimeout time.Duration
	LookupIP         func(context.Context, string) ([]net.IPAddr, error)
}
```

### `Options`

Options configures the SSO plugin.

```go
type Options struct {
	DefaultSSO                []DefaultProvider
	ProvidersLimit            *int
	ProvidersLimitForUser     func(context.Context, storage.Record) (int, error)
	ModelName                 string
	Fields                    ProviderFieldNames
	SAML                      SAMLRuntimeOptions
	OIDC                      OIDCRuntimeOptions
	DomainVerification        DomainVerificationOptions
	DisableImplicitSignUp     bool
	TrustEmailVerified        bool
	DefaultOverrideUserInfo   bool
	RedirectURI               string
	OrganizationProvisioning  OrganizationProvisioningOptions
	ProvisionUser             func(context.Context, ProvisionUserInput) error
	ProvisionUserOnEveryLogin bool
	Runtime                   Runtime
}
```

### `OrganizationAssignmentContext`

OrganizationAssignmentContext contains the endpoint-context facilities used
by AssignOrganizationByDomain.

```go
type OrganizationAssignmentContext struct {
	Adapter   storage.TransactionAdapter
	HasPlugin func(string) bool
	Clock     func() time.Time
}
```

### `OrganizationAssignmentUser`

OrganizationAssignmentUser contains the single-auth user fields required by
domain-based organization provisioning. Fields preserves caller-defined
user fields for custom role selection.

```go
type OrganizationAssignmentUser struct {
	ID     string
	Email  string
	Fields storage.Record
}
```

### `OrganizationProvisioningOptions`

OrganizationProvisioningOptions controls automatic membership creation.

```go
type OrganizationProvisioningOptions struct {
	Disabled    bool
	DefaultRole string
	GetRole     func(context.Context, OrganizationRoleInput) (string, error)
}
```

### `OrganizationRoleInput`

OrganizationRoleInput is passed to a custom domain-provisioning role
resolver. UserInfo is empty for domain assignment, matching single-auth.

```go
type OrganizationRoleInput struct {
	User     OrganizationAssignmentUser
	UserInfo storage.Record
	Provider storage.Record
	Token    *oauth2.Tokens
}
```

### `ProviderFieldNames`

ProviderFieldNames maps canonical SSO provider fields to physical database
columns while Go code continues to use the canonical storage contract.

```go
type ProviderFieldNames struct {
	Issuer         string
	OIDCConfig     string
	SAMLConfig     string
	UserID         string
	ProviderID     string
	OrganizationID string
	Domain         string
}
```

### `ProvisionUserInput`

ProvisionUserInput contains the persisted user and normalized provider data
observed after a successful SSO identity/account transaction.

```go
type ProvisionUserInput struct {
	User     storage.Record
	UserInfo storage.Record
	Tokens   oauth2.Tokens
	Provider SSOProviderProfile
}
```

### `Runtime`

Runtime is filled automatically by NewFactory. It remains public so the
transport-neutral engine plugin can be embedded without the root package.

```go
type Runtime struct {
	Clock                func() time.Time
	Random               io.Reader
	Adapter              storage.TransactionAdapter
	AdapterForContext    func(context.Context) storage.TransactionAdapter
	HasPlugin            func(string) bool
	ReservedProviderID   func(string) bool
	ResolveBaseURL       func(contract.Request) (string, error)
	IsTrustedOrigin      func(contract.Request, string, bool) (bool, error)
	CreateOAuthState     func(*engine.Context, singleauth.PluginOAuthStateInput) (singleauth.PluginOAuthState, error)
	ConsumeOAuthState    func(*engine.Context, string) (singleauth.PluginOAuthStateData, error)
	OAuthErrorURL        func(contract.Request) string
	CreateVerification   func(context.Context, string, string, time.Time) (storage.Record, error)
	PeekVerification     func(context.Context, string) (storage.Record, error)
	ConsumeVerification  func(context.Context, string) (storage.Record, error)
	ReserveVerification  func(context.Context, string, string, time.Time) (bool, error)
	HandleOAuthUser      func(*engine.Context, singleauth.PluginOAuthUserInput) (singleauth.PluginOAuthUserResult, error)
	RefreshSession       func(*engine.Context, singleauth.PluginSessionState, bool) error
	NewSession           func(*engine.Context) *singleauth.PluginSessionState
	ResolveSession       func(*engine.Context, singleauth.PluginSessionMode) (*singleauth.PluginSessionState, error)
	DeleteSession        func(context.Context, string) error
	ExpireSessionCookies func(*engine.Context)
	OnAPIErrorURL        string
	UpdateVerification   func(context.Context, string, storage.Record) error
	DeleteVerification   func(context.Context, string) error
}
```

### `SAMLConfig`

SAMLConfig contains the service-provider values needed for an
SP-initiated SAML login request.

```go
type SAMLConfig struct {
	Issuer                  string           `json:"issuer"`
	EntryPoint              string           `json:"entryPoint"`
	Certificate             string           `json:"cert"`
	CallbackURL             string           `json:"callbackUrl"`
	IDPInitiatedCallbackURL string           `json:"idpInitiatedCallbackUrl,omitempty"`
	Audience                string           `json:"audience,omitempty"`
	IdentifierFormat        string           `json:"identifierFormat,omitempty"`
	WantAssertionsSigned    bool             `json:"wantAssertionsSigned,omitempty"`
	AuthnRequestsSigned     bool             `json:"authnRequestsSigned,omitempty"`
	SignatureAlgorithm      string           `json:"signatureAlgorithm,omitempty"`
	DigestAlgorithm         string           `json:"digestAlgorithm,omitempty"`
	PrivateKey              string           `json:"privateKey,omitempty"`
	AdditionalParams        map[string]any   `json:"additionalParams,omitempty"`
	Mapping                 SAMLMapping      `json:"mapping,omitempty"`
	IDPMetadata             *SAMLIDPMetadata `json:"idpMetadata,omitempty"`
	SPMetadata              *SAMLSPMetadata  `json:"spMetadata,omitempty"`
}
```

### `SAMLIDPMetadata`

SAMLIDPMetadata is the callback-relevant subset of single-auth's IdP
metadata configuration. Metadata XML can supply the entity ID, SSO endpoint,
and all active signing certificates using the same precedence as Better
Auth's IdP helper.

```go
type SAMLIDPMetadata struct {
	Metadata             string                `json:"metadata,omitempty"`
	EntityID             string                `json:"entityID,omitempty"`
	Certificate          string                `json:"cert,omitempty"`
	PrivateKey           string                `json:"privateKey,omitempty"`
	PrivateKeyPass       string                `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted bool                  `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string                `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string                `json:"encPrivateKeyPass,omitempty"`
	SingleSignOnService  []SAMLServiceEndpoint `json:"singleSignOnService,omitempty"`
	SingleLogoutService  []SAMLServiceEndpoint `json:"singleLogoutService,omitempty"`
}
```

### `SAMLMapping`

SAMLMapping maps assertion attribute names onto single-auth's normalized
OAuth user shape. Empty fields use the provider defaults.

```go
type SAMLMapping struct {
	ID            string            `json:"id,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}
```

### `SAMLRuntimeOptions`

SAMLRuntimeOptions controls the native SAML validation pipeline. Pointer
booleans retain single-auth's secure defaults while permitting explicit
false values.

```go
type SAMLRuntimeOptions struct {
	RequestTTL                   time.Duration
	ClockSkew                    time.Duration
	RequireTimestamps            bool
	EnableInResponseToValidation *bool
	AllowIDPInitiated            *bool
	EnableReplayProtection       *bool
	MaxResponseSize              int
	MaxMetadataSize              int
	SignatureRequirement         saml.SignatureRequirement
	Algorithms                   saml.AlgorithmValidationOptions
	IDPInitiatedCallbackURL      string
	EnableSingleLogout           bool
	LogoutRequestTTL             time.Duration
	WantLogoutRequestSigned      bool
	WantLogoutResponseSigned     bool
}
```

### `SAMLSPMetadata`

SAMLSPMetadata is the callback-relevant subset of single-auth's service
provider metadata configuration.

```go
type SAMLSPMetadata struct {
	Metadata             string `json:"metadata,omitempty"`
	EntityID             string `json:"entityID,omitempty"`
	Binding              string `json:"binding,omitempty"`
	PrivateKey           string `json:"privateKey,omitempty"`
	PrivateKeyPass       string `json:"privateKeyPass,omitempty"`
	IsAssertionEncrypted bool   `json:"isAssertionEncrypted,omitempty"`
	EncPrivateKey        string `json:"encPrivateKey,omitempty"`
	EncPrivateKeyPass    string `json:"encPrivateKeyPass,omitempty"`
}
```

### `SAMLServiceEndpoint`

SAMLServiceEndpoint is one binding endpoint in explicit IdP/SP metadata.

```go
type SAMLServiceEndpoint struct {
	Binding          string `json:"Binding"`
	Location         string `json:"Location"`
	ResponseLocation string `json:"ResponseLocation,omitempty"`
}
```

### `SSOProviderProfile`

SSOProviderProfile is the provider record supplied to provisioning hooks.

```go
type SSOProviderProfile struct {
	ProviderID     string
	Issuer         string
	Domain         string
	OrganizationID string
	DomainVerified bool
	OIDCConfig     *OIDCConfig
	SAMLConfig     *SAMLConfig
}
```

