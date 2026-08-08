package providers

// Profile is the lossless JSON object used for provider profiles. Individual
// profile aliases below mirror the the reference implementation exports while retaining custom
// claims that providers may add over time.
type Profile = map[string]any

type AppleProfile = Profile
type AppleNonConformUser = AuthorizationUser
type AtlassianProfile = Profile
type CognitoProfile = Profile
type DiscordProfile = Profile
type DropboxProfile = Profile
type FacebookProfile = Profile
type FigmaProfile = Profile
type GithubProfile = Profile
type GitHubProfile = Profile
type GitlabProfile = Profile
type GitLabProfile = Profile
type GoogleProfile = Profile
type HuggingFaceProfile = Profile
type KakaoProfile = Profile
type KickProfile = Profile
type LineIDTokenPayload = Profile
type LineIdTokenPayload = Profile
type LineUserInfo = Profile
type LinearUser = Profile
type LinearProfile = Profile
type LinkedInProfile = Profile
type MicrosoftEntraIDProfile = Profile
type NaverProfile = Profile
type NotionProfile = Profile
type PaybinProfile = Profile
type PayPalProfile = Profile
type RailwayProfile = Profile
type RedditProfile = Profile
type RobloxProfile = Profile
type SalesforceProfile = Profile
type SlackProfile = Profile
type SpotifyProfile = Profile
type TiktokProfile = Profile
type TwitchProfile = Profile
type TwitterProfile = Profile
type VercelProfile = Profile
type VKProfile = Profile
type VkProfile = Profile
type WeChatProfile = Profile
type ZoomProfile = Profile

// Provider-specific option aliases preserve discoverable names without
// duplicating the shared superset representation.
type AppleOptions = Options
type AtlassianOptions = Options
type CognitoOptions = Options
type DiscordOptions = Options
type DropboxOptions = Options
type FacebookOptions = Options
type FigmaOptions = Options
type GithubOptions = Options
type GitHubOptions = Options
type GitlabOptions = Options
type GitLabOptions = Options
type GoogleOptions = Options
type HuggingFaceOptions = Options
type KakaoOptions = Options
type KickOptions = Options
type LineOptions = Options
type LinearOptions = Options
type LinkedInOptions = Options
type MicrosoftOptions = Options
type NaverOptions = Options
type NotionOptions = Options
type PaybinOptions = Options
type PayPalOptions = Options
type RailwayOptions = Options
type RedditOptions = Options
type RobloxOptions = Options
type SalesforceOptions = Options
type SlackOptions = Options
type SpotifyOptions = Options
type TiktokOptions = Options
type TwitchOptions = Options
type TwitterOptions = Options
type TwitterOption = Options
type VercelOptions = Options
type VKOptions = Options
type VkOption = Options
type WeChatOptions = Options
type ZoomOptions = Options

type SocialProvider = string
type SocialProviders = map[string]Options

type LoginType int
type AccountStatus string
type PronounOption int

const (
	AccountStatusPending  AccountStatus = "pending"
	AccountStatusActive   AccountStatus = "active"
	AccountStatusInactive AccountStatus = "inactive"
)

type PhoneNumber struct {
	Code     string `json:"code"`
	Country  string `json:"country"`
	Label    string `json:"label"`
	Number   string `json:"number"`
	Verified bool   `json:"verified"`
}

type PayPalTokenResponse struct {
	Scope        string `json:"scope,omitempty"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	Nonce        string `json:"nonce,omitempty"`
}
