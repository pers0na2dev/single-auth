package oauthprovider

import (
	"context"
	"io"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
)

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

const (
	defaultAccessTokenLifetime  = time.Hour
	defaultM2MTokenLifetime     = time.Hour
	defaultIDTokenLifetime      = 10 * time.Hour
	defaultRefreshTokenLifetime = 30 * 24 * time.Hour
	defaultCodeLifetime         = 10 * time.Minute
)

// Client is the native Go representation of an OAuth provider client. Fields
// use RFC 7591 JSON names on the wire and the existing oauthClient schema in
// storage.
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

// Session is the authenticated root session exposed to server callbacks.
type Session struct {
	Session storage.Record
	User    storage.Record
}

type ClientPrivilegeAction string

const (
	ClientPrivilegeCreate ClientPrivilegeAction = "create"
	ClientPrivilegeRead   ClientPrivilegeAction = "read"
	ClientPrivilegeUpdate ClientPrivilegeAction = "update"
	ClientPrivilegeDelete ClientPrivilegeAction = "delete"
	ClientPrivilegeList   ClientPrivilegeAction = "list"
	ClientPrivilegeRotate ClientPrivilegeAction = "rotate"
)

type ClientPrivilegeFunc func(context.Context, ClientPrivilegeAction, *Session) (bool, error)
type ClientReferenceFunc func(context.Context, *Session) (string, error)
type RequestURIResolver func(context.Context, string, string) (map[string]string, error)
type CustomUserInfoClaimsFunc func(context.Context, storage.Record, []string, map[string]any) (map[string]any, error)
type CustomIDTokenClaimsFunc func(context.Context, storage.Record, []string, Client) (map[string]any, error)
type CustomAccessTokenClaimsFunc func(context.Context, storage.Record, []string, Client, string) (map[string]any, error)

// Options configures the complete native OAuth 2.1/OIDC authorization-server
// plugin. It intentionally contains only server-side concepts applicable to a
// Go deployment.
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

type serverRuntime struct {
	adapter           storage.Adapter
	adapterForContext func(context.Context) storage.TransactionAdapter
	clock             func() time.Time
	random            io.Reader
	secret            string
	resolveBaseURL    func(contract.Request) (string, error)
	resolveSession    func(*engine.Context, bool) (*Session, error)
	deleteSession     func(context.Context, string) error
	encryptSecret     func([]byte) (string, error)
	decryptSecret     func(string) ([]byte, error)
	listEndpoints     func() []engine.Endpoint
	hasJWTPlugin      bool
}

var _ singleauth.PluginFactory = (*Factory)(nil)
