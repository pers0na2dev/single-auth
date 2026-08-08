// Package providers ports the built-in the reference implementation 1.6.26 social providers.
//
// The package intentionally keeps provider policy (scope ordering, endpoint
// selection, token authentication, profile mapping and provider quirks) out of
// the transport-neutral OAuth primitives in package oauth2.
package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

// Builtins is the the reference implementation 1.6.26 socialProviderList in source order.
var Builtins = []string{
	"apple", "atlassian", "cognito", "discord", "facebook", "figma",
	"github", "microsoft", "google", "huggingface", "slack", "spotify",
	"twitch", "twitter", "dropbox", "kick", "linear", "linkedin",
	"gitlab", "tiktok", "reddit", "roblox", "salesforce", "vk", "zoom",
	"notion", "kakao", "naver", "line", "paybin", "paypal",
	"railway", "vercel", "wechat",
}

var (
	ErrUnknownProvider           = errors.New("unknown social provider")
	ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrClientSecretRequired      = errors.New("CLIENT_SECRET_REQUIRED")
	ErrDomainAndRegionRequired   = errors.New("DOMAIN_AND_REGION_REQUIRED")
	ErrCodeVerifierRequired      = errors.New("codeVerifier is required")
	ErrFailedToGetAccessToken    = errors.New("FAILED_TO_GET_ACCESS_TOKEN")
	ErrFailedToRefreshToken      = errors.New("FAILED_TO_REFRESH_ACCESS_TOKEN")
)

// AuthorizationInput is the argument accepted by every provider authorization
// URL builder. Empty values have the same meaning as undefined upstream.
type AuthorizationInput struct {
	State        string
	CodeVerifier string
	Scopes       []string
	RedirectURI  string
	Display      string
	LoginHint    string
}

// CodeInput is the argument accepted by authorization-code exchanges.
type CodeInput struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}

// AuthorizationUser carries Apple's non-conforming callback user object.
type AuthorizationUser struct {
	FirstName string
	LastName  string
	Email     string
}

// UserInfoResult contains the normalized user and the provider profile used to
// create it. Data deliberately remains an object map so provider-only claims
// are not discarded.
type UserInfoResult struct {
	User oauth2.UserInfo
	Data map[string]any
}

// UserInfoFunc overrides the provider user-info implementation.
type UserInfoFunc func(context.Context, oauth2.Tokens) (*UserInfoResult, error)

// RefreshFunc overrides the provider refresh implementation.
type RefreshFunc func(context.Context, string) (oauth2.Tokens, error)

// VerifyIDTokenFunc overrides provider ID-token verification.
type VerifyIDTokenFunc func(context.Context, string, string) (bool, error)

// MapProfileFunc mirrors mapProfileToUser. Recognized keys are id, name,
// email, image and emailVerified; every other key is retained in User.Extra.
type MapProfileFunc func(context.Context, map[string]any) (map[string]any, error)

// Options is the union of the options accepted by the supported built-ins.
// Provider-specific fields are ignored by providers that do not consume them.
type Options struct {
	ClientID     any
	ClientSecret string
	ClientKey    string
	Scopes       []string

	DisableDefaultScope   bool
	RedirectURI           string
	AuthorizationEndpoint string
	DisableIDTokenSignIn  bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	Prompt                string
	ResponseMode          string
	OverrideUserInfo      bool

	HTTPClient         *http.Client
	GetUserInfo        UserInfoFunc
	RefreshAccessToken RefreshFunc
	VerifyIDToken      VerifyIDTokenFunc
	MapProfileToUser   MapProfileFunc

	// Apple.
	AppBundleIdentifier string
	Audience            any
	// Atlassian, PayPal, Salesforce.
	Environment string
	// Cognito.
	Domain              string
	Region              string
	UserPoolID          string
	RequireClientSecret bool
	// Discord.
	Permissions *int
	// Dropbox and Google.
	AccessType string
	// Facebook.
	Fields   []string
	ConfigID string
	// GitLab and Paybin.
	Issuer string
	// Google.
	Display      string
	HostedDomain string
	// Microsoft Entra ID.
	TenantID            string
	Authority           string
	ProfilePhotoSize    int
	DisableProfilePhoto bool
	// PayPal.
	RequestShippingAddress bool
	// Reddit.
	Duration string
	// Salesforce.
	LoginURL string
	// Twitch.
	Claims []string
	// VK.
	Scheme string
	// WeChat.
	PlatformType string
	Language     string
	// Zoom. Nil means the reference implementation's default (enabled).
	PKCE *bool
}

// Metadata exposes the concrete endpoints and defaults frozen from the
// the reference implementation source. Endpoints selected from options (tenant, issuer,
// environment, and so on) are reflected after construction.
type Metadata struct {
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	JWKSURI               string
	DefaultScopes         []string
	TokenAuthentication   oauth2.Authentication
	SupportsRefresh       bool
	SupportsIDToken       bool
}

// Provider is a configured social provider.
type Provider struct {
	ID       string
	Name     string
	Options  Options
	Metadata Metadata

	createAuthorizationURL func(AuthorizationInput) (*url.URL, error)
	validateCode           func(context.Context, CodeInput) (*oauth2.Tokens, error)
	refreshToken           func(context.Context, string) (oauth2.Tokens, error)
	getUserInfo            func(context.Context, oauth2.Tokens, *AuthorizationUser) (*UserInfoResult, error)
	verifyIDToken          func(context.Context, string, string) (bool, error)
}

func (p *Provider) CreateAuthorizationURL(input AuthorizationInput) (*url.URL, error) {
	return p.createAuthorizationURL(input)
}

func (p *Provider) ValidateAuthorizationCode(ctx context.Context, input CodeInput) (*oauth2.Tokens, error) {
	return p.validateCode(p.withHTTPClient(ctx), input)
}

func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (oauth2.Tokens, error) {
	if p.refreshToken == nil {
		return oauth2.Tokens{}, errors.New("provider does not support refresh tokens")
	}
	if p.Options.RefreshAccessToken != nil {
		return p.Options.RefreshAccessToken(p.withHTTPClient(ctx), refreshToken)
	}
	return p.refreshToken(p.withHTTPClient(ctx), refreshToken)
}

func (p *Provider) GetUserInfo(ctx context.Context, tokens oauth2.Tokens, authorizationUser ...AuthorizationUser) (*UserInfoResult, error) {
	if p.Options.GetUserInfo != nil {
		return p.Options.GetUserInfo(p.withHTTPClient(ctx), tokens)
	}
	var user *AuthorizationUser
	if len(authorizationUser) != 0 {
		user = &authorizationUser[0]
	}
	return p.getUserInfo(p.withHTTPClient(ctx), tokens, user)
}

func (p *Provider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error) {
	if p.Options.DisableIDTokenSignIn {
		return false, nil
	}
	if p.Options.VerifyIDToken != nil {
		return p.Options.VerifyIDToken(p.withHTTPClient(ctx), token, nonce)
	}
	if p.verifyIDToken == nil {
		return false, nil
	}
	return p.verifyIDToken(p.withHTTPClient(ctx), token, nonce)
}

type httpClientContextKey struct{}

func (p *Provider) withHTTPClient(ctx context.Context) context.Context {
	if p == nil || p.Options.HTTPClient == nil {
		return ctx
	}
	return context.WithValue(ctx, httpClientContextKey{}, p.Options.HTTPClient)
}

func (p *Provider) clientFor(ctx context.Context) *http.Client {
	if ctx != nil {
		if client, ok := ctx.Value(httpClientContextKey{}).(*http.Client); ok && client != nil {
			return client
		}
	}
	return p.client()
}

func (p *Provider) client() *http.Client {
	if p.Options.HTTPClient != nil {
		return p.Options.HTTPClient
	}
	return http.DefaultClient
}
