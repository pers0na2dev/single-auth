// Package oidcprovider implements the frozen single-auth 1.6.26
// oidc-provider plugin. The package name deliberately omits the dash used by
// the TypeScript plugin ID so it can be imported as ordinary Go.
package oidcprovider

import (
	"context"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

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

const (
	defaultCodeExpiresIn         = 10 * time.Minute
	defaultAccessTokenExpiresIn  = time.Hour
	defaultRefreshTokenExpiresIn = 7 * 24 * time.Hour
)

// ClientSecretStorageMode controls how dynamically registered client secrets
// are persisted. The plaintext secret is always returned once to the client.
type ClientSecretStorageMode string

const (
	ClientSecretPlain            ClientSecretStorageMode = "plain"
	ClientSecretHashed           ClientSecretStorageMode = "hashed"
	ClientSecretEncrypted        ClientSecretStorageMode = "encrypted"
	ClientSecretCustomHash       ClientSecretStorageMode = "custom-hash"
	ClientSecretCustomEncryption ClientSecretStorageMode = "custom-encryption"
)

// ClientSecretHashFunc is used for custom one-way client-secret storage.
type ClientSecretHashFunc func(context.Context, string) (string, error)

// ClientSecretCryptFunc is used for custom reversible client-secret storage.
type ClientSecretCryptFunc func(context.Context, string) (string, error)

// AdditionalUserInfoClaimFunc adds claims to userinfo and ID-token payloads.
// Returned entries override built-in claims, matching object-spread order in
// single-auth 1.6.26.
type AdditionalUserInfoClaimFunc func(
	context.Context,
	storage.Record,
	[]string,
	Client,
) (map[string]any, error)

// ConsentHTMLInput is passed to GetConsentHTML when no external consent page
// is configured.
type ConsentHTMLInput struct {
	ClientID       string
	ClientName     string
	ClientIcon     *string
	ClientMetadata map[string]any
	Code           string
	Scopes         []string
}

// ConsentHTMLFunc renders the inline consent document.
type ConsentHTMLFunc func(context.Context, ConsentHTMLInput) (string, error)

// Client is the normalized oauthApplication record accepted by trusted-client
// configuration and returned by client lookup.
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

// Options configures the deprecated single-auth OIDC provider. Zero token and
// code durations select the frozen upstream defaults. RequirePKCE deliberately
// remains false by default because that is the actual 1.6.26 implementation,
// despite the historical TypeScript documentation saying otherwise.
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

type ResolveSessionFunc func(*engine.Context, bool) (*SessionState, error)
type ContextAdapterResolver func(context.Context) storage.TransactionAdapter
type VerificationCreateFunc func(context.Context, string, string, time.Time) (storage.Record, error)
type VerificationReadFunc func(context.Context, string) (storage.Record, error)
type VerificationUpdateFunc func(context.Context, string, storage.Record) error
type VerificationDeleteFunc func(context.Context, string) error
type BaseURLResolver func(contract.Request) (string, error)
type SessionCookieResolver func(contract.Request) (string, cookies.Options)
type FindSessionFunc func(context.Context, string) (*SessionState, error)
type NewSessionFunc func(*engine.Context) *SessionState
type DeleteSessionFunc func(context.Context, string) error
type TrustedOriginFunc func(contract.Request, string, bool) (bool, error)
type JWTPluginSignFunc func(*engine.Context, map[string]any, string, string, int64) (string, error)
type JWTPluginVerifyFunc func(*engine.Context, string, string) (map[string]any, error)

// Runtime contains dependencies injected by NewFactory. Explicit runtime
// values also make New useful in focused engine tests.
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

// SessionState is the root session/user pair visible to authorization and
// logout handlers.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// AuthorizationCodeValue is the persisted authorization/consent state.
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

// AccessToken is the normalized oauthAccessToken record.
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

// OAuthErrorBody is the RFC-compatible error representation.
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

var _ singleauth.PluginFactory = (*rootFactory)(nil)
