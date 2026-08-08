---
title: "Social providers"
---

Configure the 34 built-in OAuth and OpenID Connect identity providers.

The `providers` package contains 34 native Go server integrations. Every built-in creates authorization URLs, exchanges authorization codes, and normalizes profiles. Refresh and provider-specific ID-token verification are available only where the provider metadata table says they are implemented.

> **Info: Server-side scope**
>
> These pages document the Go server. They do not require or describe a JavaScript client. Start social sign-in by posting to the HTTP route or by calling the typed direct API.

## Register a provider

~~~go
google, err := providers.Google(providers.Options{
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        google.ID: google,
    },
})
~~~

The callback URL to register with Google is `https://auth.example.com/api/auth/callback/google`. Replace the host, base path, and provider ID for your deployment.

> **Warning: Authorization-code callback boundary**
>
> The normal authorization-code callback exchanges the code and calls the provider's user-info mapper; it does not automatically call `Provider.VerifyIDToken`. The verifier column on each provider page applies to the direct ID-token sign-in/link path and to explicit calls to that method.

## Built-in providers

| Provider | Constructor | Default callback path |
| --- | --- | --- |
| [Apple](./apple.md) | `providers.Apple` | `/api/auth/callback/apple` |
| [Atlassian](./atlassian.md) | `providers.Atlassian` | `/api/auth/callback/atlassian` |
| [Amazon Cognito](./cognito.md) | `providers.Cognito` | `/api/auth/callback/cognito` |
| [Discord](./discord.md) | `providers.Discord` | `/api/auth/callback/discord` |
| [Facebook](./facebook.md) | `providers.Facebook` | `/api/auth/callback/facebook` |
| [Figma](./figma.md) | `providers.Figma` | `/api/auth/callback/figma` |
| [GitHub](./github.md) | `providers.GitHub` | `/api/auth/callback/github` |
| [Microsoft Entra ID](./microsoft.md) | `providers.Microsoft` | `/api/auth/callback/microsoft` |
| [Google](./google.md) | `providers.Google` | `/api/auth/callback/google` |
| [Hugging Face](./huggingface.md) | `providers.HuggingFace` | `/api/auth/callback/huggingface` |
| [Slack](./slack.md) | `providers.Slack` | `/api/auth/callback/slack` |
| [Spotify](./spotify.md) | `providers.Spotify` | `/api/auth/callback/spotify` |
| [Twitch](./twitch.md) | `providers.Twitch` | `/api/auth/callback/twitch` |
| [X (Twitter)](./twitter.md) | `providers.Twitter` | `/api/auth/callback/twitter` |
| [Dropbox](./dropbox.md) | `providers.Dropbox` | `/api/auth/callback/dropbox` |
| [Kick](./kick.md) | `providers.Kick` | `/api/auth/callback/kick` |
| [Linear](./linear.md) | `providers.Linear` | `/api/auth/callback/linear` |
| [LinkedIn](./linkedin.md) | `providers.LinkedIn` | `/api/auth/callback/linkedin` |
| [GitLab](./gitlab.md) | `providers.GitLab` | `/api/auth/callback/gitlab` |
| [TikTok](./tiktok.md) | `providers.TikTok` | `/api/auth/callback/tiktok` |
| [Reddit](./reddit.md) | `providers.Reddit` | `/api/auth/callback/reddit` |
| [Roblox](./roblox.md) | `providers.Roblox` | `/api/auth/callback/roblox` |
| [Salesforce](./salesforce.md) | `providers.Salesforce` | `/api/auth/callback/salesforce` |
| [VK ID](./vk.md) | `providers.VK` | `/api/auth/callback/vk` |
| [Zoom](./zoom.md) | `providers.Zoom` | `/api/auth/callback/zoom` |
| [Notion](./notion.md) | `providers.Notion` | `/api/auth/callback/notion` |
| [Kakao](./kakao.md) | `providers.Kakao` | `/api/auth/callback/kakao` |
| [Naver](./naver.md) | `providers.Naver` | `/api/auth/callback/naver` |
| [LINE](./line.md) | `providers.LINE` | `/api/auth/callback/line` |
| [Paybin](./paybin.md) | `providers.Paybin` | `/api/auth/callback/paybin` |
| [PayPal](./paypal.md) | `providers.PayPal` | `/api/auth/callback/paypal` |
| [Railway](./railway.md) | `providers.Railway` | `/api/auth/callback/railway` |
| [Vercel](./vercel.md) | `providers.Vercel` | `/api/auth/callback/vercel` |
| [WeChat](./wechat.md) | `providers.WeChat` | `/api/auth/callback/wechat` |

## Shared route flow

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| `POST` | `/api/auth/sign-in/social` | Public; trusted-origin checks apply | Create OAuth state and return or follow the provider authorization URL. |
| `GET`, `POST` | `/api/auth/callback/:id` | OAuth state/cookie | Validate the callback, exchange the code, create or link an account, and create a session. |
| `POST` | `/api/auth/link-social` | Session | Link a provider account to the current user. |
| `GET` | `/api/auth/list-accounts` | Session | List the current user's credential and social accounts. |
| `POST` | `/api/auth/get-access-token` | Session | Return a usable provider access token, refreshing it when necessary. |
| `POST` | `/api/auth/refresh-token` | Session | Refresh and persist provider tokens explicitly. |
| `POST` | `/api/auth/unlink-account` | Session | Remove one linked provider account subject to account-linking policy. |

Read [Common options](./common-options.md) before configuring overrides, and use [Custom provider](./custom-provider.md) only when no built-in matches the remote identity service.
