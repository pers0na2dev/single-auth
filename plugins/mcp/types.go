package mcp

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

const (
	defaultCodeExpiresIn         = 10 * time.Minute
	defaultAccessTokenExpiresIn  = time.Hour
	defaultRefreshTokenExpiresIn = 7 * 24 * time.Hour
)

// AdditionalUserInfoClaimFunc adds claims to an ID token. Returned claims
// take precedence over the built-in profile and email claims, matching the
// object-spread order in single-auth 1.6.26.
type AdditionalUserInfoClaimFunc func(
	context.Context,
	storage.Record,
	[]string,
	Client,
) (map[string]any, error)

// OIDCOptions is the MCP plugin's embedded OIDC-provider configuration.
// Zero durations select single-auth's defaults.
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

// Options configures the MCP OAuth server.
type Options struct {
	LoginPage  string
	Resource   string
	OIDCConfig OIDCOptions
	Schema     storage.Schema
	Runtime    Runtime
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

// Runtime contains dependencies injected by NewFactory. It remains public so
// the transport-neutral descriptor can also be embedded without the root
// Auth constructor in focused protocol tests.
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

// SessionState is the root session/user pair visible during authorization.
type SessionState struct {
	Session storage.Record
	User    storage.Record
}

// Client is the normalized oauthApplication model used by authorization and
// token endpoints.
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

// AccessToken is the oauthAccessToken representation returned by
// getMcpSession and used by resource-server middleware.
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

type codeVerificationValue struct {
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

// OAuthErrorBody is the wire representation used by the token and consent
// endpoints while the direct API retains a typed APIError.
type OAuthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// PluginFactory is retained as a compile-time assertion/documentation alias
// for callers that keep plugin factories in typed collections.
var _ singleauth.PluginFactory = (*rootFactory)(nil)
