---
title: "github.com/pers0na2dev/single-auth/protocol/providers"
---

Exported server-side Go API for github.com/pers0na2dev/single-auth/protocol/providers.

- Import path: `github.com/pers0na2dev/single-auth/protocol/providers`
- Package name: `providers`

Package providers ports the built-in the reference implementation 1.6.26 social providers.

The package intentionally keeps provider policy (scope ordering, endpoint
selection, token authentication, profile mapping and provider quirks) out of
the transport-neutral OAuth primitives in package oauth2.

## Constants

ReferenceBaseline is the exact upstream release represented by Builtins.

```go
const ReferenceBaseline = "1.6.26"
```

## Variables

```go
var (
	ErrUnknownProvider           = errors.New("unknown social provider")
	ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")
	ErrClientSecretRequired      = errors.New("CLIENT_SECRET_REQUIRED")
	ErrDomainAndRegionRequired   = errors.New("DOMAIN_AND_REGION_REQUIRED")
	ErrCodeVerifierRequired      = errors.New("codeVerifier is required")
	ErrFailedToGetAccessToken    = errors.New("FAILED_TO_GET_ACCESS_TOKEN")
	ErrFailedToRefreshToken      = errors.New("FAILED_TO_REFRESH_ACCESS_TOKEN")
)
```

Builtins is the the reference implementation 1.6.26 socialProviderList in source order.

```go
var Builtins = []string{
	"apple", "atlassian", "cognito", "discord", "facebook", "figma",
	"github", "microsoft", "google", "huggingface", "slack", "spotify",
	"twitch", "twitter", "dropbox", "kick", "linear", "linkedin",
	"gitlab", "tiktok", "reddit", "roblox", "salesforce", "vk", "zoom",
	"notion", "kakao", "naver", "line", "paybin", "paypal",
	"railway", "vercel", "wechat",
}
```

## Functions

### `GetApplePublicKey`

```go
func GetApplePublicKey(ctx context.Context, kid string, clients ...*http.Client) (crypto.PublicKey, error)
```

### `GetCognitoPublicKey`

```go
func GetCognitoPublicKey(ctx context.Context, kid, region, userPoolID string, clients ...*http.Client) (crypto.PublicKey, error)
```

### `GetGooglePublicKey`

```go
func GetGooglePublicKey(ctx context.Context, kid string, clients ...*http.Client) (crypto.PublicKey, error)
```

### `GetMicrosoftPublicKey`

```go
func GetMicrosoftPublicKey(ctx context.Context, kid, tenant, authority string, clients ...*http.Client) (crypto.PublicKey, error)
```

### `GetPayPalPublicKey`

```go
func GetPayPalPublicKey(ctx context.Context, kid, jwksURI string, clients ...*http.Client) (crypto.PublicKey, error)
```

### `IsGoogleHostedDomainAllowed`

```go
func IsGoogleHostedDomainAllowed(configuredHostedDomain string, tokenHostedDomain any) bool
```

### `PublicKeyFromJWK`

PublicKeyFromJWK imports the RSA or EC key types used by the built-ins.

```go
func PublicKeyFromJWK(jwk JWK) (crypto.PublicKey, error)
```

### `SocialProviderList`

SocialProviderList returns a defensive copy of the frozen built-in list.

```go
func SocialProviderList() []string
```

### `VerifyGoogleIDToken`

VerifyGoogleIDToken mirrors the reference implementation's exported helper. Invalid tokens
return a nil claims object and nil error; transport/configuration errors are
likewise treated as failed verification by the upstream helper.

```go
func VerifyGoogleIDToken(ctx context.Context, options VerifyGoogleIDTokenOptions) (map[string]any, error)
```

### `WithVerifyIDTokenRequestContext`

WithVerifyIDTokenRequestContext returns a context carrying an independent
copy of the request metadata supplied to a custom ID-token verifier.

```go
func WithVerifyIDTokenRequestContext(ctx context.Context, requestContext VerifyIDTokenRequestContext) context.Context
```

## Types

### `AccountStatus`

```go
type AccountStatus string
```

## Constants associated with `AccountStatus`

```go
const (
	AccountStatusPending  AccountStatus = "pending"
	AccountStatusActive   AccountStatus = "active"
	AccountStatusInactive AccountStatus = "inactive"
)
```

### `AppleNonConformUser`

```go
type AppleNonConformUser = AuthorizationUser
```

### `AppleOptions`

Provider-specific option aliases preserve discoverable names without
duplicating the shared superset representation.

```go
type AppleOptions = Options
```

### `AppleProfile`

```go
type AppleProfile = Profile
```

### `AtlassianOptions`

```go
type AtlassianOptions = Options
```

### `AtlassianProfile`

```go
type AtlassianProfile = Profile
```

### `AuthorizationInput`

AuthorizationInput is the argument accepted by every provider authorization
URL builder. Empty values have the same meaning as undefined upstream.

```go
type AuthorizationInput struct {
	State        string
	CodeVerifier string
	Scopes       []string
	RedirectURI  string
	Display      string
	LoginHint    string
}
```

### `AuthorizationUser`

AuthorizationUser carries Apple's non-conforming callback user object.

```go
type AuthorizationUser struct {
	FirstName string
	LastName  string
	Email     string
}
```

### `CodeInput`

CodeInput is the argument accepted by authorization-code exchanges.

```go
type CodeInput struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	DeviceID     string
}
```

### `CognitoOptions`

```go
type CognitoOptions = Options
```

### `CognitoProfile`

```go
type CognitoProfile = Profile
```

### `CustomProvider`

CustomProvider describes a fully configured provider implementation. It is
primarily intended for protocol plugins that must register providers at
PluginFactory build time while retaining the root account/token lifecycle.
All callbacks are snapshotted by NewCustomProvider.

```go
type CustomProvider struct {
	ID       string
	Name     string
	Options  Options
	Metadata Metadata

	CreateAuthorizationURL    func(AuthorizationInput) (*url.URL, error)
	ValidateAuthorizationCode func(context.Context, CodeInput) (*oauth2.Tokens, error)
	RefreshAccessToken        func(context.Context, string) (oauth2.Tokens, error)
	GetUserInfo               func(context.Context, oauth2.Tokens, *AuthorizationUser) (*UserInfoResult, error)
	VerifyIDToken             func(context.Context, string, string) (bool, error)
}
```

### `DiscordOptions`

```go
type DiscordOptions = Options
```

### `DiscordProfile`

```go
type DiscordProfile = Profile
```

### `DropboxOptions`

```go
type DropboxOptions = Options
```

### `DropboxProfile`

```go
type DropboxProfile = Profile
```

### `FacebookOptions`

```go
type FacebookOptions = Options
```

### `FacebookProfile`

```go
type FacebookProfile = Profile
```

### `FigmaOptions`

```go
type FigmaOptions = Options
```

### `FigmaProfile`

```go
type FigmaProfile = Profile
```

### `GitHubOptions`

```go
type GitHubOptions = Options
```

### `GitHubProfile`

```go
type GitHubProfile = Profile
```

### `GitLabOptions`

```go
type GitLabOptions = Options
```

### `GitLabProfile`

```go
type GitLabProfile = Profile
```

### `GithubOptions`

```go
type GithubOptions = Options
```

### `GithubProfile`

```go
type GithubProfile = Profile
```

### `GitlabOptions`

```go
type GitlabOptions = Options
```

### `GitlabProfile`

```go
type GitlabProfile = Profile
```

### `GoogleOptions`

```go
type GoogleOptions = Options
```

### `GoogleProfile`

```go
type GoogleProfile = Profile
```

### `HuggingFaceOptions`

```go
type HuggingFaceOptions = Options
```

### `HuggingFaceProfile`

```go
type HuggingFaceProfile = Profile
```

### `JWK`

JWK is one JSON Web Key from a provider's published key set.

```go
type JWK = map[string]any
```

## Constructors and functions for `JWK`

### `FetchJWK`

FetchJWK returns the key matching kid. Provider key fetches intentionally
use ordinary fetch redirect behavioral compatibility, matching the reference implementation's exported key
helpers rather than the stricter shared token endpoint helper.

```go
func FetchJWK(ctx context.Context, client *http.Client, jwksURI, kid string) (JWK, error)
```

### `KakaoOptions`

```go
type KakaoOptions = Options
```

### `KakaoProfile`

```go
type KakaoProfile = Profile
```

### `KickOptions`

```go
type KickOptions = Options
```

### `KickProfile`

```go
type KickProfile = Profile
```

### `LineIDTokenPayload`

```go
type LineIDTokenPayload = Profile
```

### `LineIdTokenPayload`

```go
type LineIdTokenPayload = Profile
```

### `LineOptions`

```go
type LineOptions = Options
```

### `LineUserInfo`

```go
type LineUserInfo = Profile
```

### `LinearOptions`

```go
type LinearOptions = Options
```

### `LinearProfile`

```go
type LinearProfile = Profile
```

### `LinearUser`

```go
type LinearUser = Profile
```

### `LinkedInOptions`

```go
type LinkedInOptions = Options
```

### `LinkedInProfile`

```go
type LinkedInProfile = Profile
```

### `LoginType`

```go
type LoginType int
```

### `MapProfileFunc`

MapProfileFunc mirrors mapProfileToUser. Recognized keys are id, name,
email, image and emailVerified; every other key is retained in User.Extra.

```go
type MapProfileFunc func(context.Context, map[string]any) (map[string]any, error)
```

### `Metadata`

Metadata exposes the concrete endpoints and defaults frozen from the
the reference implementation source. Endpoints selected from options (tenant, issuer,
environment, or explicit endpoint overrides) are reflected after construction.

```go
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
```

### `MicrosoftEntraIDProfile`

```go
type MicrosoftEntraIDProfile = Profile
```

### `MicrosoftOptions`

```go
type MicrosoftOptions = Options
```

### `NaverOptions`

```go
type NaverOptions = Options
```

### `NaverProfile`

```go
type NaverProfile = Profile
```

### `NotionOptions`

```go
type NotionOptions = Options
```

### `NotionProfile`

```go
type NotionProfile = Profile
```

### `Options`

Options is the union of the options accepted by the supported built-ins.
Provider-specific fields are ignored by providers that do not consume them.

```go
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
```

### `PayPalOptions`

```go
type PayPalOptions = Options
```

### `PayPalProfile`

```go
type PayPalProfile = Profile
```

### `PayPalTokenResponse`

```go
type PayPalTokenResponse struct {
	Scope        string `json:"scope,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Nonce        string `json:"nonce,omitempty"`
}
```

### `PaybinOptions`

```go
type PaybinOptions = Options
```

### `PaybinProfile`

```go
type PaybinProfile = Profile
```

### `PhoneNumber`

```go
type PhoneNumber struct {
	Code     string `json:"code"`
	Country  string `json:"country"`
	Label    string `json:"label"`
	Number   string `json:"number"`
	Verified bool   `json:"verified"`
}
```

### `Profile`

Profile is the lossless JSON object used for provider profiles. Individual
profile aliases below mirror the the reference implementation exports while retaining custom
claims that providers may add over time.

```go
type Profile = map[string]any
```

### `PronounOption`

```go
type PronounOption int
```

### `Provider`

Provider is a configured social provider.

```go
type Provider struct {
	ID       string
	Name     string
	Options  Options
	Metadata Metadata
	// contains filtered or unexported fields
}
```

## Constructors and functions for `Provider`

### `Apple`

```go
func Apple(options Options) (*Provider, error)
```

### `Atlassian`

```go
func Atlassian(options Options) (*Provider, error)
```

### `Cognito`

```go
func Cognito(options Options) (*Provider, error)
```

### `Discord`

```go
func Discord(options Options) (*Provider, error)
```

### `Dropbox`

```go
func Dropbox(options Options) (*Provider, error)
```

### `Facebook`

```go
func Facebook(options Options) (*Provider, error)
```

### `Figma`

```go
func Figma(options Options) (*Provider, error)
```

### `GitHub`

```go
func GitHub(options Options) (*Provider, error)
```

### `GitLab`

```go
func GitLab(options Options) (*Provider, error)
```

### `Google`

```go
func Google(options Options) (*Provider, error)
```

### `HuggingFace`

```go
func HuggingFace(options Options) (*Provider, error)
```

### `Kakao`

```go
func Kakao(options Options) (*Provider, error)
```

### `Kick`

```go
func Kick(options Options) (*Provider, error)
```

### `LINE`

```go
func LINE(options Options) (*Provider, error)
```

### `Linear`

```go
func Linear(options Options) (*Provider, error)
```

### `LinkedIn`

```go
func LinkedIn(options Options) (*Provider, error)
```

### `Microsoft`

```go
func Microsoft(options Options) (*Provider, error)
```

### `Naver`

```go
func Naver(options Options) (*Provider, error)
```

### `New`

New configures one of the supported the reference implementation 1.6.26 built-ins.

```go
func New(id string, options Options) (*Provider, error)
```

### `NewCustomProvider`

NewCustomProvider creates a provider backed by caller-supplied OAuth
primitives. Required callbacks are validated up front so malformed plugin
registrations cannot become request-time nil function panics.

```go
func NewCustomProvider(input CustomProvider) (*Provider, error)
```

### `Notion`

```go
func Notion(options Options) (*Provider, error)
```

### `PayPal`

```go
func PayPal(options Options) (*Provider, error)
```

### `Paybin`

```go
func Paybin(options Options) (*Provider, error)
```

### `Railway`

```go
func Railway(options Options) (*Provider, error)
```

### `Reddit`

```go
func Reddit(options Options) (*Provider, error)
```

### `Roblox`

```go
func Roblox(options Options) (*Provider, error)
```

### `Salesforce`

```go
func Salesforce(options Options) (*Provider, error)
```

### `Slack`

```go
func Slack(options Options) (*Provider, error)
```

### `Spotify`

```go
func Spotify(options Options) (*Provider, error)
```

### `TikTok`

```go
func TikTok(options Options) (*Provider, error)
```

### `Twitch`

```go
func Twitch(options Options) (*Provider, error)
```

### `Twitter`

```go
func Twitter(options Options) (*Provider, error)
```

### `VK`

```go
func VK(options Options) (*Provider, error)
```

### `Vercel`

```go
func Vercel(options Options) (*Provider, error)
```

### `WeChat`

```go
func WeChat(options Options) (*Provider, error)
```

### `Zoom`

```go
func Zoom(options Options) (*Provider, error)
```

## Methods on `Provider`

### `CreateAuthorizationURL`

```go
func (p *Provider) CreateAuthorizationURL(input AuthorizationInput) (*url.URL, error)
```

### `GetUserInfo`

```go
func (p *Provider) GetUserInfo(ctx context.Context, tokens oauth2.Tokens, authorizationUser ...AuthorizationUser) (*UserInfoResult, error)
```

### `RefreshAccessToken`

```go
func (p *Provider) RefreshAccessToken(ctx context.Context, refreshToken string) (oauth2.Tokens, error)
```

### `ValidateAuthorizationCode`

```go
func (p *Provider) ValidateAuthorizationCode(ctx context.Context, input CodeInput) (*oauth2.Tokens, error)
```

### `VerifyIDToken`

```go
func (p *Provider) VerifyIDToken(ctx context.Context, token, nonce string) (bool, error)
```

### `VerifyIDTokenWithRequestContext`

VerifyIDTokenWithRequestContext verifies an ID token while forwarding the
endpoint request metadata to a custom VerifyIDToken callback.

```go
func (p *Provider) VerifyIDTokenWithRequestContext(
	ctx context.Context,
	token string,
	nonce string,
	requestContext VerifyIDTokenRequestContext,
) (bool, error)
```

### `RailwayOptions`

```go
type RailwayOptions = Options
```

### `RailwayProfile`

```go
type RailwayProfile = Profile
```

### `RedditOptions`

```go
type RedditOptions = Options
```

### `RedditProfile`

```go
type RedditProfile = Profile
```

### `RefreshFunc`

RefreshFunc overrides the provider refresh implementation.

```go
type RefreshFunc func(context.Context, string) (oauth2.Tokens, error)
```

### `RobloxOptions`

```go
type RobloxOptions = Options
```

### `RobloxProfile`

```go
type RobloxProfile = Profile
```

### `SalesforceOptions`

```go
type SalesforceOptions = Options
```

### `SalesforceProfile`

```go
type SalesforceProfile = Profile
```

### `SlackOptions`

```go
type SlackOptions = Options
```

### `SlackProfile`

```go
type SlackProfile = Profile
```

### `SocialProvider`

```go
type SocialProvider = string
```

### `SocialProviders`

```go
type SocialProviders = map[string]Options
```

### `SpotifyOptions`

```go
type SpotifyOptions = Options
```

### `SpotifyProfile`

```go
type SpotifyProfile = Profile
```

### `TiktokOptions`

```go
type TiktokOptions = Options
```

### `TiktokProfile`

```go
type TiktokProfile = Profile
```

### `TwitchOptions`

```go
type TwitchOptions = Options
```

### `TwitchProfile`

```go
type TwitchProfile = Profile
```

### `TwitterOption`

```go
type TwitterOption = Options
```

### `TwitterOptions`

```go
type TwitterOptions = Options
```

### `TwitterProfile`

```go
type TwitterProfile = Profile
```

### `UserInfoFunc`

UserInfoFunc overrides the provider user-info implementation.

```go
type UserInfoFunc func(context.Context, oauth2.Tokens) (*UserInfoResult, error)
```

### `UserInfoResult`

UserInfoResult contains the normalized user and the provider profile used to
create it. Data deliberately remains an object map so provider-only claims
are not discarded.

```go
type UserInfoResult struct {
	User oauth2.UserInfo
	Data map[string]any
}
```

### `VKOptions`

```go
type VKOptions = Options
```

### `VKProfile`

```go
type VKProfile = Profile
```

### `VercelOptions`

```go
type VercelOptions = Options
```

### `VercelProfile`

```go
type VercelProfile = Profile
```

### `VerifyGoogleIDTokenOptions`

```go
type VerifyGoogleIDTokenOptions struct {
	Token      string
	Audience   any
	Nonce      string
	HTTPClient *http.Client
}
```

### `VerifyIDTokenFunc`

VerifyIDTokenFunc overrides provider ID-token verification.

```go
type VerifyIDTokenFunc func(context.Context, string, string) (bool, error)
```

### `VerifyIDTokenRequestContext`

VerifyIDTokenRequestContext is the transport-neutral request metadata made
available to a custom ID-token verifier. It is the Go counterpart of the
GenericEndpointContext argument passed by the reference implementation 1.6.26.

```go
type VerifyIDTokenRequestContext struct {
	Headers http.Header
}
```

## Constructors and functions for `VerifyIDTokenRequestContext`

### `VerifyIDTokenRequestContextFrom`

VerifyIDTokenRequestContextFrom returns the request metadata forwarded to a
custom ID-token verifier. The returned headers may be mutated independently.

```go
func VerifyIDTokenRequestContextFrom(ctx context.Context) (VerifyIDTokenRequestContext, bool)
```

### `VkOption`

```go
type VkOption = Options
```

### `VkProfile`

```go
type VkProfile = Profile
```

### `WeChatOptions`

```go
type WeChatOptions = Options
```

### `WeChatProfile`

```go
type WeChatProfile = Profile
```

### `ZoomOptions`

```go
type ZoomOptions = Options
```

### `ZoomProfile`

```go
type ZoomProfile = Profile
```

