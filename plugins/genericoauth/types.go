package genericoauth

import (
	"context"
	"io"
	"net/http"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/logger"
	"github.com/pers0na2dev/single-auth/protocol/oauth2"
	"github.com/pers0na2dev/single-auth/protocol/providers"
	"github.com/pers0na2dev/single-auth/storage"
)

const Version = "1.6.26"

// Profile is the lossless JSON object returned by a generic OAuth user-info
// endpoint. Numeric account IDs remain numeric until the final normalization
// step, matching single-auth's string | number input contract.
type Profile map[string]any

// TokenRequest is supplied to a provider-specific authorization-code
// exchange. CodeVerifier is empty when PKCE is disabled.
type TokenRequest struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}

type GetTokenFunc func(context.Context, TokenRequest) (oauth2.Tokens, error)
type GetUserInfoFunc func(context.Context, oauth2.Tokens) (Profile, error)
type MapProfileToUserFunc func(context.Context, Profile) (Profile, error)
type EndpointParamsFunc func(*engine.Context) map[string]string

// ParamSource accepts either static endpoint parameters or a request-scoped
// resolver. When both are set, Resolve takes precedence, like single-auth's
// record-or-function option.
type ParamSource struct {
	Static  map[string]string
	Resolve EndpointParamsFunc
}

// Config mirrors single-auth 1.6.26 GenericOAuthConfig. AccessTokenExpiresIn
// is a Go duration; zero preserves an unknown expiry when the provider omits
// expires_in.
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

type Options struct {
	Config  []Config
	Runtime Runtime
}

// Runtime is the transport-neutral host surface required by the standalone
// plugin. NewFactory binds it to singleauth.Auth.
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

// SignInInput is the direct API equivalent of POST /sign-in/oauth2.
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

// LinkInput is the direct API equivalent of POST /oauth2/link.
type LinkInput struct {
	ProviderID       string
	CallbackURL      string
	Scopes           []string
	ErrorCallbackURL string
}

type discoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

type oauthStateData struct {
	CallbackURL   string
	CodeVerifier  string
	ErrorURL      string
	NewUserURL    string
	OAuthState    string
	ExpiresAt     int64
	RequestSignUp *bool
	Link          *oauthLinkState
	Raw           map[string]any
}

type oauthLinkState struct {
	Email  string `json:"email"`
	UserID string `json:"userId"`
}
