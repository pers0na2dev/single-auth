package providers

import "fmt"

// ReferenceBaseline is the exact upstream release represented by Builtins.
const ReferenceBaseline = "1.6.26"

// New configures one of the supported the reference implementation 1.6.26 built-ins.
func New(id string, options Options) (*Provider, error) {
	switch id {
	case "apple":
		return Apple(options)
	case "atlassian":
		return Atlassian(options)
	case "cognito":
		return Cognito(options)
	case "discord":
		return Discord(options)
	case "dropbox":
		return Dropbox(options)
	case "facebook":
		return Facebook(options)
	case "figma":
		return Figma(options)
	case "github":
		return GitHub(options)
	case "gitlab":
		return GitLab(options)
	case "google":
		return Google(options)
	case "huggingface":
		return HuggingFace(options)
	case "kakao":
		return Kakao(options)
	case "kick":
		return Kick(options)
	case "line":
		return LINE(options)
	case "linear":
		return Linear(options)
	case "linkedin":
		return LinkedIn(options)
	case "microsoft":
		return Microsoft(options)
	case "naver":
		return Naver(options)
	case "notion":
		return Notion(options)
	case "paybin":
		return Paybin(options)
	case "paypal":
		return PayPal(options)
	case "railway":
		return Railway(options)
	case "reddit":
		return Reddit(options)
	case "roblox":
		return Roblox(options)
	case "salesforce":
		return Salesforce(options)
	case "slack":
		return Slack(options)
	case "spotify":
		return Spotify(options)
	case "tiktok":
		return TikTok(options)
	case "twitch":
		return Twitch(options)
	case "twitter":
		return Twitter(options)
	case "vercel":
		return Vercel(options)
	case "vk":
		return VK(options)
	case "wechat":
		return WeChat(options)
	case "zoom":
		return Zoom(options)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownProvider, id)
	}
}

// SocialProviderList returns a defensive copy of the frozen built-in list.
func SocialProviderList() []string { return cloneStrings(Builtins) }
