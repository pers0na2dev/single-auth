package sso

import (
	"context"
	"io"
	"net"
	"net/http"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/saml"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// DefaultProvider is an application-configured SSO provider. It takes
// precedence over database providers, matching single-auth's defaultSSO
// option.
type DefaultProvider struct {
	ProviderID string
	Domain     string
	SAMLConfig SAMLConfig
	OIDCConfig *OIDCConfig
}

// OIDCMapping maps OIDC claims onto single-auth's normalized OAuth user
// shape. Empty fields use sub, email, email_verified, name, and picture.
type OIDCMapping struct {
	ID            string            `json:"id,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	Image         string            `json:"image,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

// OIDCConfig is the persisted and application-configured SSO OIDC provider
// contract. PKCE defaults to enabled when omitted.
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

// OIDCRuntimeOptions controls outbound discovery, token, UserInfo, and JWKS
// requests. LookupIP is injectable for deterministic SSRF/DNS-rebinding tests.
type OIDCRuntimeOptions struct {
	HTTPClient       *http.Client
	DiscoveryTimeout time.Duration
	LookupIP         func(context.Context, string) ([]net.IPAddr, error)
}

// SSOProviderProfile is the provider record supplied to provisioning hooks.
type SSOProviderProfile struct {
	ProviderID     string
	Issuer         string
	Domain         string
	OrganizationID string
	DomainVerified bool
	OIDCConfig     *OIDCConfig
	SAMLConfig     *SAMLConfig
}

// ProvisionUserInput contains the persisted user and normalized provider data
// observed after a successful SSO identity/account transaction.
type ProvisionUserInput struct {
	User     storage.Record
	UserInfo storage.Record
	Tokens   oauth2.Tokens
	Provider SSOProviderProfile
}

// SAMLMapping maps assertion attribute names onto single-auth's normalized
// OAuth user shape. Empty fields use the provider defaults.
type SAMLMapping struct {
	ID            string            `json:"id,omitempty"`
	Email         string            `json:"email,omitempty"`
	EmailVerified string            `json:"emailVerified,omitempty"`
	Name          string            `json:"name,omitempty"`
	FirstName     string            `json:"firstName,omitempty"`
	LastName      string            `json:"lastName,omitempty"`
	ExtraFields   map[string]string `json:"extraFields,omitempty"`
}

// SAMLIDPMetadata is the callback-relevant subset of single-auth's IdP
// metadata configuration. Metadata XML can supply the entity ID, SSO endpoint,
// and all active signing certificates using the same precedence as Better
// Auth's IdP helper.
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

// SAMLServiceEndpoint is one binding endpoint in explicit IdP/SP metadata.
type SAMLServiceEndpoint struct {
	Binding          string `json:"Binding"`
	Location         string `json:"Location"`
	ResponseLocation string `json:"ResponseLocation,omitempty"`
}

// SAMLSPMetadata is the callback-relevant subset of single-auth's service
// provider metadata configuration.
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

// SAMLConfig contains the service-provider values needed for an
// SP-initiated SAML login request.
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

// SAMLRuntimeOptions controls the native SAML validation pipeline. Pointer
// booleans retain single-auth's secure defaults while permitting explicit
// false values.
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

// Options configures the SSO plugin.
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

// ProviderFieldNames maps canonical SSO provider fields to physical database
// columns while Go code continues to use the canonical storage contract.
type ProviderFieldNames struct {
	Issuer         string
	OIDCConfig     string
	SAMLConfig     string
	UserID         string
	ProviderID     string
	OrganizationID string
	Domain         string
}

// DomainVerificationOptions controls whether persisted SSO providers carry
// the verification marker used by domain-based organization assignment.
type DomainVerificationOptions struct {
	Enabled     bool
	TokenPrefix string
	LookupTXT   func(context.Context, string) ([]string, error)
}

// Runtime is filled automatically by NewFactory. It remains public so the
// transport-neutral engine plugin can be embedded without the root package.
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
