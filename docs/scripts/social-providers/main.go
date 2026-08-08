package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pers0na2dev/single-auth/protocol/providers"
)

type providerDoc struct {
	ID             string
	Title          string
	Constructor    string
	CredentialNote string
	Configuration  []configDoc
	Options        []optionDoc
	Notes          []string
}

type configDoc struct {
	Name       string
	Expression string
}

type optionDoc struct {
	Name        string
	Description string
}

var providerDocs = []providerDoc{
	{ID: "apple", Title: "Apple", Constructor: "Apple", CredentialNote: "Create a Services ID and a Sign in with Apple key. The configured redirect URI must use HTTPS outside local development.", Options: options(
		"AppBundleIdentifier", "Optional native-app bundle identifier added to the accepted ID-token audiences.",
		"Audience", "A string or list of additional accepted ID-token audiences; falls back to AppBundleIdentifier and then ClientID.",
	), Notes: []string{"Authorization uses `form_post` and requests both an authorization code and an ID token.", "Apple may only return the user's name on the first authorization; the callback-specific user object is preserved when it is present.", "The verifier used by direct ID-token sign-in checks Apple's JWKS, issuer, audience, token age, and nonce."}},
	{ID: "atlassian", Title: "Atlassian", Constructor: "Atlassian", CredentialNote: "Create an OAuth 2.0 (3LO) app in the Atlassian developer console and register the exact callback URL.", Notes: []string{"The authorization request includes Atlassian's audience and offline-access requirements.", "Both client credentials and PKCE are required when the authorization URL is created."}},
	{ID: "cognito", Title: "Amazon Cognito", Constructor: "Cognito", CredentialNote: "Configure an app client and hosted UI domain in the Cognito user pool.", Options: options(
		"Domain", "Required Cognito hosted UI domain, with or without an http(s) scheme.",
		"Region", "Required AWS region used to construct the issuer and JWKS URI.",
		"UserPoolID", "Required Cognito user-pool ID.",
		"RequireClientSecret", "When true, construction/sign-in requires a client secret in addition to the client ID.",
	), Configuration: config(
		"ClientID", `os.Getenv("COGNITO_CLIENT_ID")`,
		"ClientSecret", `os.Getenv("COGNITO_CLIENT_SECRET")`,
		"Domain", `os.Getenv("COGNITO_DOMAIN")`,
		"Region", `os.Getenv("COGNITO_REGION")`,
		"UserPoolID", `os.Getenv("COGNITO_USER_POOL_ID")`,
	), Notes: []string{"The constructor rejects missing Domain, Region, or UserPoolID.", "Profile data is decoded from the ID token first and falls back to the user-info endpoint; that mapping step does not itself verify the token signature.", "The verifier used by direct ID-token sign-in checks the user-pool issuer, JWKS, audience, token age, and nonce."}},
	{ID: "discord", Title: "Discord", Constructor: "Discord", CredentialNote: "Create a Discord OAuth2 application and add the callback URL in its redirect settings.", Options: options("Permissions", "Optional Discord permission bit field included in the authorization request."), Notes: []string{"The default identity scope is intentionally minimal; add application-specific scopes explicitly."}},
	{ID: "facebook", Title: "Facebook", Constructor: "Facebook", CredentialNote: "Create a Meta app, enable Facebook Login, and register the callback URL as a valid OAuth redirect URI.", Options: options(
		"Fields", "Overrides the profile fields requested from the Graph API.",
		"ConfigID", "Adds a Facebook Login for Business configuration ID to authorization requests.",
	), Notes: []string{"The profile request is built from the configured Fields list.", "Email availability depends on the Facebook app permissions and the user's account."}},
	{ID: "figma", Title: "Figma", Constructor: "Figma", CredentialNote: "Create an OAuth app in Figma and register the callback URL.", Notes: []string{"Figma uses HTTP Basic client authentication for token exchange.", "PKCE and both client credentials are required."}},
	{ID: "github", Title: "GitHub", Constructor: "GitHub", CredentialNote: "Create a GitHub OAuth App and set its authorization callback URL.", Notes: []string{"If the primary profile omits an email address, the provider queries the authenticated email endpoint, chooses the primary entry or falls back to the first entry, and then carries that entry's verified flag.", "PKCE is included in the authorization-code flow."}},
	{ID: "microsoft", Title: "Microsoft Entra ID", Constructor: "Microsoft", CredentialNote: "Register an application in Microsoft Entra ID, add a Web redirect URI, and create a client secret.", Options: options(
		"TenantID", "Tenant selector; defaults to common. It may be a tenant ID, organizations, consumers, or common.",
		"Authority", "OAuth authority base URL; defaults to https://login.microsoftonline.com.",
		"ProfilePhotoSize", "Requested square Microsoft Graph profile-photo size; defaults to 48.",
		"DisableProfilePhoto", "Skips embedding the Microsoft Graph profile photo in the normalized user.",
	), Notes: []string{"Tenant-aware issuer checks prevent consumer/organization tokens from crossing a restricted tenant mode in the direct ID-token verifier.", "The default scopes include offline_access and User.Read.", "The direct verifier checks the authority JWKS, audience, token age, nonce, tenant, and issuer.", "The profile path currently requests the photo even when DisableProfilePhoto is true; the option only prevents embedding a successful response."}},
	{ID: "google", Title: "Google", Constructor: "Google", CredentialNote: "Create an OAuth 2.0 Web application in Google Cloud and register the callback URL.", Options: options(
		"AccessType", "Authorization access_type value, commonly offline when a refresh token is needed.",
		"Display", "Optional Google authorization display mode.",
		"HostedDomain", "Restricts the hd claim. Use * to require any hosted domain, or an exact domain to require that domain.",
	), Notes: []string{"PKCE and both client credentials are required.", "Profile data is decoded from the ID token; that mapping step does not itself verify the token signature.", "The verifier used by direct ID-token sign-in checks Google's issuers, JWKS, audience, token age, nonce, and HostedDomain policy."}},
	{ID: "huggingface", Title: "Hugging Face", Constructor: "HuggingFace", CredentialNote: "Create an OAuth application in Hugging Face and register the callback URL.", Notes: []string{"The provider requests OpenID Connect profile and email claims by default.", "PKCE is used."}},
	{ID: "slack", Title: "Slack", Constructor: "Slack", CredentialNote: "Create a Slack app, enable Sign in with Slack, and add the callback URL under OAuth & Permissions.", Notes: []string{"This built-in is the social sign-in provider. The Generic OAuth plugin also exposes a Slack helper for custom OAuth configurations."}},
	{ID: "spotify", Title: "Spotify", Constructor: "Spotify", CredentialNote: "Create an application in the Spotify developer dashboard and register the callback URL.", Notes: []string{"The default scope requests the account email.", "PKCE is used during code exchange."}},
	{ID: "twitch", Title: "Twitch", Constructor: "Twitch", CredentialNote: "Create a Twitch application and register the callback URL.", Options: options("Claims", "Optional OIDC claims requested during authorization."), Notes: []string{"Twitch identity data is decoded from the returned ID token, but this built-in does not expose a provider-specific ID-token verifier. Use a custom verified profile callback when signature verification is required."}},
	{ID: "twitter", Title: "X (Twitter)", Constructor: "Twitter", CredentialNote: "Create an OAuth 2.0 application in the X developer portal and register the callback URL.", Notes: []string{"The OAuth 2.0 authorization-code flow uses PKCE.", "The provider requests confirmed_email separately; if it is unavailable, the normalized email falls back to the username and is not marked verified."}},
	{ID: "dropbox", Title: "Dropbox", Constructor: "Dropbox", CredentialNote: "Create a Dropbox app, enable OAuth, and add the callback URL.", Options: options("AccessType", "Maps to Dropbox token_access_type, for example offline for refresh-token access."), Notes: []string{"The profile endpoint is called with POST as required by Dropbox.", "PKCE is used."}},
	{ID: "kick", Title: "Kick", Constructor: "Kick", CredentialNote: "Create a Kick application and register the callback URL.", Notes: []string{"The provider uses PKCE and normalizes Kick's nested user response."}},
	{ID: "linear", Title: "Linear", Constructor: "Linear", CredentialNote: "Create a Linear OAuth application and register the callback URL.", Notes: []string{"The default scopes are taken from the frozen upstream implementation 1.6.26 provider behavior."}},
	{ID: "linkedin", Title: "LinkedIn", Constructor: "LinkedIn", CredentialNote: "Create a LinkedIn application, request the Sign In with LinkedIn using OpenID Connect product, and add the callback URL.", Notes: []string{"The provider requests profile, email, and openid by default.", "The authorization request carries LoginHint when supplied."}},
	{ID: "gitlab", Title: "GitLab", Constructor: "GitLab", CredentialNote: "Create an OAuth application in GitLab and register the callback URL.", Options: options("Issuer", "GitLab base URL; defaults to https://gitlab.com and enables self-managed GitLab instances."), Notes: []string{"Locked or non-active GitLab profiles are rejected.", "PKCE is used."}},
	{ID: "tiktok", Title: "TikTok", Constructor: "TikTok", CredentialNote: "Create a TikTok Login Kit application and register the callback URL.", Configuration: config(
		"ClientKey", `os.Getenv("TIKTOK_CLIENT_KEY")`,
		"ClientSecret", `os.Getenv("TIKTOK_CLIENT_SECRET")`,
	), Notes: []string{"TikTok uses ClientKey, not ClientID, in authorization and token requests.", "The normalized email is the returned username and is not marked verified.", "This built-in currently does not apply MapProfileToUser to TikTok profile results."}},
	{ID: "reddit", Title: "Reddit", Constructor: "Reddit", CredentialNote: "Create a Reddit web application and set its redirect URI to the callback URL.", Options: options("Duration", "Optional Reddit authorization duration, such as permanent for refresh-token access."), Notes: []string{"Token exchange uses HTTP Basic authentication and Reddit's required User-Agent.", "When Reddit does not expose an email, the provider creates a stable `<id>@reddit.invalid` placeholder unless MapProfileToUser supplies one.", "This provider intentionally does not add PKCE to the authorization request."}},
	{ID: "roblox", Title: "Roblox", Constructor: "Roblox", CredentialNote: "Create an OAuth 2.0 application in Roblox and register the callback URL.", Notes: []string{"The provider uses Roblox's OpenID Connect identity endpoints.", "For compatibility with the frozen provider behavior, preferred_username is placed in the normalized Email field and is not marked verified; do not treat it as a deliverable email address."}},
	{ID: "salesforce", Title: "Salesforce", Constructor: "Salesforce", CredentialNote: "Create a Salesforce Connected App and add the callback URL.", Options: options(
		"Environment", "Set to sandbox to use test.salesforce.com; every other value uses login.salesforce.com unless LoginURL is set.",
		"LoginURL", "Host name only, without a scheme, used to build `https://<host>/services/oauth2/*` endpoints.",
	), Notes: []string{"PKCE and both client credentials are required.", "Use LoginURL for a My Domain host rather than rewriting individual endpoints."}},
	{ID: "vk", Title: "VK ID", Constructor: "VK", CredentialNote: "Create a VK ID application and register the callback URL.", Notes: []string{"VK's code exchange carries the device ID returned by the authorization callback.", "PKCE is used.", "The provider returns no identity when VK supplies no email and MapProfileToUser does not supply one."}},
	{ID: "zoom", Title: "Zoom", Constructor: "Zoom", CredentialNote: "Create a Zoom OAuth application and add the callback URL to its allow list.", Options: options("PKCE", "Pointer boolean controlling PKCE. Nil means enabled, matching the default."), Notes: []string{"Token exchange uses client credentials in the POST body.", "PKCE is enabled by default and can be explicitly disabled only when required by an existing Zoom app."}},
	{ID: "notion", Title: "Notion", Constructor: "Notion", CredentialNote: "Create a public Notion integration and register the callback URL.", Notes: []string{"Authorization requests identify the owner as a user.", "Authorization-code exchange uses HTTP Basic client authentication; refresh sends the client credentials in the POST body."}},
	{ID: "kakao", Title: "Kakao", Constructor: "Kakao", CredentialNote: "Create a Kakao application, enable Kakao Login, and register the callback URL.", Notes: []string{"The provider maps Kakao account and profile nesting and marks email verified only when Kakao reports both validity and verification.", "The authorization request does not use PKCE."}},
	{ID: "naver", Title: "Naver", Constructor: "Naver", CredentialNote: "Register an application with Naver Login and configure the callback URL.", Notes: []string{"Only successful Naver resultcode 00 responses are accepted.", "The authorization request does not use PKCE."}},
	{ID: "line", Title: "LINE", Constructor: "LINE", CredentialNote: "Create a LINE Login channel and add the callback URL.", Notes: []string{"Profile data is decoded from the ID token first and falls back to user info; decoding does not itself verify the token.", "The direct ID-token verifier calls LINE's verification endpoint.", "PKCE is used."}},
	{ID: "paybin", Title: "Paybin", Constructor: "Paybin", CredentialNote: "Create a Paybin OAuth client and register the callback URL.", Options: options("Issuer", "Overrides the Paybin issuer/base URL when using a non-default deployment."), Notes: []string{"PKCE is used and the provider supports issuer-based endpoint selection.", "Profile data is decoded from the ID token, but this built-in does not expose a provider-specific ID-token verifier."}},
	{ID: "paypal", Title: "PayPal", Constructor: "PayPal", CredentialNote: "Create a PayPal REST app and register the callback URL.", Options: options(
		"Environment", "Empty or sandbox selects sandbox endpoints; every other value selects production endpoints.",
	), Notes: []string{"Sandbox is the default; set a non-sandbox value explicitly for production.", "The direct ID-token verifier supports HS256 with the client secret and RS256 with PayPal JWKS, and constrains issuer, audience, age, and nonce."}},
	{ID: "railway", Title: "Railway", Constructor: "Railway", CredentialNote: "Create a Railway OAuth application and register the callback URL.", Notes: []string{"Token exchange uses HTTP Basic client authentication.", "The provider requests OpenID Connect profile and email scopes."}},
	{ID: "vercel", Title: "Vercel", Constructor: "Vercel", CredentialNote: "Create a Vercel integration and register the callback URL.", Notes: []string{"PKCE is used.", "The provider normalizes Vercel account profile data into the common user shape."}},
	{ID: "wechat", Title: "WeChat", Constructor: "WeChat", CredentialNote: "Create a WeChat Open Platform application and configure its OAuth callback domain.", Options: options(
		"Language", "Authorization-language value; defaults to cn. The user-info request currently uses zh_CN.",
	), Notes: []string{"The token response's openid is retained for the user-info request.", "When WeChat does not return an email, the provider creates a stable `<id>@wechat.invalid` placeholder.", "The current built-in always uses the Open Platform qrconnect endpoint; PlatformType is a compatibility field with no effect."}},
}

func config(values ...string) []configDoc {
	result := make([]configDoc, 0, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		result = append(result, configDoc{Name: values[index], Expression: values[index+1]})
	}
	return result
}

func options(values ...string) []optionDoc {
	result := make([]optionDoc, 0, len(values)/2)
	for index := 0; index < len(values); index += 2 {
		result = append(result, optionDoc{Name: values[index], Description: values[index+1]})
	}
	return result
}

func main() {
	root, err := os.Getwd()
	check(err)
	directory := filepath.Join(root, "docs", "content", "docs", "social-providers")
	check(os.MkdirAll(directory, 0o755))

	configured := providers.Options{
		ClientID:     "YOUR_CLIENT_ID",
		ClientSecret: "YOUR_CLIENT_SECRET",
		ClientKey:    "YOUR_CLIENT_KEY",
		Domain:       "auth.example.auth.us-east-1.amazoncognito.com",
		Region:       "us-east-1",
		UserPoolID:   "us-east-1_example",
	}

	for _, item := range providerDocs {
		provider, providerErr := providers.New(item.ID, configured)
		if providerErr != nil {
			panic(fmt.Errorf("construct %s: %w", item.ID, providerErr))
		}
		check(os.WriteFile(filepath.Join(directory, item.ID+".md"), []byte(renderProvider(item, provider)), 0o644))
	}
	check(os.WriteFile(filepath.Join(directory, "index.md"), []byte(renderIndex()), 0o644))
	check(os.WriteFile(filepath.Join(directory, "common-options.md"), []byte(commonOptionsPage), 0o644))
	check(os.WriteFile(filepath.Join(directory, "custom-provider.md"), []byte(customProviderPage), 0o644))
}

func renderIndex() string {
	rows := make([]string, 0, len(providerDocs))
	for _, item := range providerDocs {
		rows = append(rows, fmt.Sprintf("| [%s](./%s.md) | `providers.%s` | `/api/auth/callback/%s` |", item.Title, item.ID, item.Constructor, item.ID))
	}
	return `---
title: "Social providers"
---

Configure the 34 built-in OAuth and OpenID Connect identity providers.

The ` + "`providers`" + ` package contains 34 native Go server integrations. Every built-in creates authorization URLs, exchanges authorization codes, and normalizes profiles. Refresh and provider-specific ID-token verification are available only where the provider metadata table says they are implemented.

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

The callback URL to register with Google is ` + "`https://auth.example.com/api/auth/callback/google`" + `. Replace the host, base path, and provider ID for your deployment.

> **Warning: Authorization-code callback boundary**
>
> The normal authorization-code callback exchanges the code and calls the provider's user-info mapper; it does not automatically call ` + "`Provider.VerifyIDToken`" + `. The verifier column on each provider page applies to the direct ID-token sign-in/link path and to explicit calls to that method.

## Built-in providers

| Provider | Constructor | Default callback path |
| --- | --- | --- |
` + strings.Join(rows, "\n") + `

## Shared route flow

| Method | Route | Authentication | Purpose |
| --- | --- | --- | --- |
| ` + "`POST`" + ` | ` + "`/api/auth/sign-in/social`" + ` | Public; trusted-origin checks apply | Create OAuth state and return or follow the provider authorization URL. |
| ` + "`GET`, `POST`" + ` | ` + "`/api/auth/callback/:id`" + ` | OAuth state/cookie | Validate the callback, exchange the code, create or link an account, and create a session. |
| ` + "`POST`" + ` | ` + "`/api/auth/link-social`" + ` | Session | Link a provider account to the current user. |
| ` + "`GET`" + ` | ` + "`/api/auth/list-accounts`" + ` | Session | List the current user's credential and social accounts. |
| ` + "`POST`" + ` | ` + "`/api/auth/get-access-token`" + ` | Session | Return a usable provider access token, refreshing it when necessary. |
| ` + "`POST`" + ` | ` + "`/api/auth/refresh-token`" + ` | Session | Refresh and persist provider tokens explicitly. |
| ` + "`POST`" + ` | ` + "`/api/auth/unlink-account`" + ` | Session | Remove one linked provider account subject to account-linking policy. |

Read [Common options](./common-options.md) before configuring overrides, and use [Custom provider](./custom-provider.md) only when no built-in matches the remote identity service.
`
}

func renderProvider(item providerDoc, provider *providers.Provider) string {
	metadata := provider.Metadata
	authentication := string(metadata.TokenAuthentication)
	if authentication == "" {
		authentication = "post (default)"
	}
	scopes := "None by default"
	if len(metadata.DefaultScopes) != 0 {
		scopes = strings.Join(metadata.DefaultScopes, ", ")
	}
	refresh := "No"
	if metadata.SupportsRefresh {
		refresh = "Yes"
	}
	idToken := "No provider-specific verifier"
	if metadata.SupportsIDToken {
		idToken = "Yes"
	}
	userInfo := metadata.UserInfoEndpoint
	if userInfo == "" {
		userInfo = "Not used by default"
	}
	jwks := metadata.JWKSURI
	if jwks == "" {
		jwks = "Not used by default"
	}

	var specific string
	if len(item.Options) == 0 {
		specific = "This provider adds no provider-only fields beyond the [common options](./common-options.md)."
	} else {
		rows := make([]string, 0, len(item.Options))
		for _, option := range item.Options {
			rows = append(rows, fmt.Sprintf("| `%s` | %s |", option.Name, option.Description))
		}
		specific = "| Field | Behavior |\n| --- | --- |\n" + strings.Join(rows, "\n")
	}

	notes := make([]string, 0, len(item.Notes))
	for _, note := range item.Notes {
		notes = append(notes, "- "+note)
	}

	configuration := item.Configuration
	if len(configuration) == 0 {
		configuration = config(
			"ClientID", fmt.Sprintf(`os.Getenv(%q)`, envName(item.ID, "CLIENT_ID")),
			"ClientSecret", fmt.Sprintf(`os.Getenv(%q)`, envName(item.ID, "CLIENT_SECRET")),
		)
	}
	configurationLines := make([]string, 0, len(configuration))
	for _, field := range configuration {
		configurationLines = append(configurationLines, fmt.Sprintf("    %-13s %s,", field.Name+":", field.Expression))
	}

	return fmt.Sprintf(`---
title: %q
---

Configure %s social sign-in in the native Go server.

Import `+"`github.com/pers0na2dev/single-auth/protocol/providers`"+` and construct the provider with `+"`providers.%s`"+`. The provider ID is `+"`%s`"+`, so its default callback URL is `+"`https://<your-auth-host>/api/auth/callback/%s`"+`.

> **Info: Provider console**
>
> %s

## Configuration

`+"```go"+`
%sProvider, err := providers.%s(providers.Options{
%s
})
if err != nil {
    return err
}

auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        %sProvider.ID: %sProvider,
    },
})
`+"```"+`

The provider constructor does not contact the remote service. Network activity starts when an authorization URL is created, a callback exchanges a code, profile data is fetched, a token is refreshed, or a remote JWKS is required.

## Provider behavior

| Property | Value |
| --- | --- |
| Authorization endpoint | `+"`%s`"+` |
| Token endpoint | `+"`%s`"+` |
| User-info endpoint | `+"`%s`"+` |
| Default scopes | `+"`%s`"+` |
| Token client authentication | `+"`%s`"+` |
| Refresh-token implementation | %s |
| Direct ID-token verifier | %s |
| JWKS URI | `+"`%s`"+` |

`+"`Options.Scopes`"+` are appended to the defaults. Set `+"`DisableDefaultScope`"+` only when the remote application is intentionally configured with a complete replacement scope set.

> **Warning: ID-token verification is flow-specific**
>
> `+"`Provider.VerifyIDToken`"+` and the verifier row above describe the direct ID-token sign-in/link path. The normal authorization-code callback currently exchanges the code and calls `+"`GetUserInfo`"+`; it does not automatically invoke that verifier. A provider that decodes an ID token while mapping a profile is not thereby verifying its signature. Use a verified custom profile callback when your callback trust model requires that additional check.

## Provider-specific options

%s

## Start sign-in

`+"```http"+`
POST /api/auth/sign-in/social HTTP/1.1
Host: auth.example.com
Content-Type: application/json
Origin: https://app.example.com

{
  "provider": "%s",
  "callbackURL": "https://app.example.com/account"
}
`+"```"+`

When `+"`callbackURL`"+` is accepted by trusted-origin validation, the server stores it in the OAuth state and returns to it after a successful callback. Configure `+"`Options.TrustedOrigins`"+` for every browser origin and callback destination your application uses.

## Direct provider API

The configured value also exposes transport-neutral primitives:

`+"```go"+`
authorizationURL, err := %sProvider.CreateAuthorizationURL(providers.AuthorizationInput{
    State:        state,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/%s",
})

tokens, err := %sProvider.ValidateAuthorizationCode(ctx, providers.CodeInput{
    Code:         code,
    CodeVerifier: verifier,
    RedirectURI:  "https://auth.example.com/api/auth/callback/%s",
})

profile, err := %sProvider.GetUserInfo(ctx, tokens)
`+"```"+`

Use those primitives only when implementing a custom server flow. The normal auth routes additionally enforce state, cookies, account-linking policy, session creation, hooks, rate limits, and trusted origins.

## Security and behavior notes

%s

- Keep the client secret in server-side configuration and never expose it to a browser.
- Register the exact callback URL, including `+"`Options.BasePath`"+` and the provider ID.
- Preserve OAuth state and PKCE cookies through the callback; do not terminate the flow on a different hostname unless cookie and trusted-origin settings are designed for it.
- Use a redirect-refusing HTTP client policy for endpoints you override, or validate every redirect target yourself.
`, item.Title, item.Title, item.Constructor, item.ID, item.ID, item.CredentialNote,
		item.ID, item.Constructor, strings.Join(configurationLines, "\n"), item.ID, item.ID,
		metadata.AuthorizationEndpoint, metadata.TokenEndpoint, userInfo, scopes, authentication, refresh, idToken, jwks,
		specific, item.ID, item.ID, item.ID, item.ID, item.ID, item.ID, strings.Join(notes, "\n"))
}

func envName(providerID, suffix string) string {
	prefix := strings.ToUpper(strings.ReplaceAll(providerID, "-", "_"))
	return prefix + "_" + suffix
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var commonOptionsPage = `---
title: "Common provider options"
---

Shared credentials, scopes, callbacks, overrides, and security controls for built-in social providers.

Every built-in constructor accepts ` + "`providers.Options`" + `. It is a superset: provider-specific fields are ignored by providers that do not consume them.

## Credentials and endpoints

| Field | Type | Behavior |
| --- | --- | --- |
| ` + "`ClientID`" + ` | ` + "`any`" + ` | A ` + "`string`" + `, ` + "`[]string`" + `, or ` + "`[]any`" + ` containing strings. The first value is used for authorization; verifier audiences may include the full list. |
| ` + "`ClientSecret`" + ` | ` + "`string`" + ` | OAuth client secret. Required by providers that authenticate confidential clients. |
| ` + "`ClientKey`" + ` | ` + "`string`" + ` | TikTok's required application key; it is also forwarded by the Notion refresh implementation when set. |
| ` + "`RedirectURI`" + ` | ` + "`string`" + ` | Explicit OAuth redirect URI. Leave empty to let the auth runtime derive ` + "`BaseURL + BasePath + /callback/:id`" + `. |
| ` + "`AuthorizationEndpoint`" + ` | ` + "`string`" + ` | Overrides an authorization endpoint where the provider supports that override. Prefer the provider-specific issuer/authority option when available. |
| ` + "`HTTPClient`" + ` | ` + "`*http.Client`" + ` | Per-provider HTTP client used for token, profile, and JWKS requests. Configure timeouts and a safe redirect policy. |

## Scope and authorization behavior

| Field | Default | Behavior |
| --- | --- | --- |
| ` + "`Scopes`" + ` | Empty | Additional scopes appended to provider defaults. |
| ` + "`DisableDefaultScope`" + ` | ` + "`false`" + ` | Uses only ` + "`Scopes`" + ` instead of provider defaults. |
| ` + "`Prompt`" + ` | Empty | Provider prompt value where supported. |
| ` + "`ResponseMode`" + ` | Empty | Compatibility field retained in the public option union; current built-in authorization builders do not consume it. |
| ` + "`DisableIDTokenSignIn`" + ` | ` + "`false`" + ` | Disables the provider's direct ID-token sign-in path and verifier. |
| ` + "`DisableImplicitSignUp`" + ` | ` + "`false`" + ` | Prevents creating a user as an implicit consequence of a sign-in flow. |
| ` + "`DisableSignUp`" + ` | ` + "`false`" + ` | Prevents new-user creation through this provider. |

## Mapping and network overrides

| Field | Signature | Use |
| --- | --- | --- |
| ` + "`GetUserInfo`" + ` | ` + "`func(context.Context, oauth2.Tokens) (*UserInfoResult, error)`" + ` | Replaces the provider's profile request and mapping. |
| ` + "`RefreshAccessToken`" + ` | ` + "`func(context.Context, string) (oauth2.Tokens, error)`" + ` | Replaces refresh-token exchange. |
| ` + "`VerifyIDToken`" + ` | ` + "`func(context.Context, string, string) (bool, error)`" + ` | Replaces provider ID-token verification. The second string is the expected nonce. |
| ` + "`MapProfileToUser`" + ` | ` + "`func(context.Context, map[string]any) (map[string]any, error)`" + ` | Adds or overrides ` + "`id`" + `, ` + "`name`" + `, ` + "`email`" + `, ` + "`image`" + `, ` + "`emailVerified`" + `, and additional user fields. |
| ` + "`OverrideUserInfo`" + ` | Boolean | Compatibility field retained in the option union; it currently has no effect in built-in providers. |

When a built-in applies ` + "`MapProfileToUser`" + `, recognized keys are applied to the normalized ` + "`oauth2.UserInfo`" + ` and unrecognized keys are retained in ` + "`UserInfo.Extra`" + `. TikTok intentionally does not invoke this callback in the current compatibility implementation.

## Compatibility fields without current behavior

` + "`RequestShippingAddress`" + `, ` + "`Scheme`" + `, and ` + "`PlatformType`" + ` remain in ` + "`providers.Options`" + ` for source compatibility but are not read by the current PayPal, VK, or WeChat implementations. ` + "`Environment`" + ` is consumed by PayPal and Salesforce only; it has no Atlassian behavior. Do not build policy around these fields until production code implements them.

## ID-token verification boundary

> **Warning: The normal callback does not invoke VerifyIDToken**
>
> ` + "`Provider.VerifyIDToken`" + ` and ` + "`Options.VerifyIDToken`" + ` are used by the direct ID-token sign-in/link path and by explicit callers. The normal authorization-code callback exchanges the code and calls ` + "`GetUserInfo`" + ` without automatically invoking the verifier. Decoding an ID token inside a profile mapper does not verify its signature.

If an authorization-code callback must cryptographically verify an ID token before accepting its claims, provide a ` + "`GetUserInfo`" + ` override that performs that verification before returning a profile, or implement a custom provider with the same rule. ` + "`DisableIDTokenSignIn`" + ` disables the separate direct ID-token path; it does not prevent a built-in callback mapper from reading an ID token returned by code exchange.

## Account and callback policy

Provider options control the remote protocol. Root ` + "`singleauth.Options`" + ` controls local security and persistence:

- ` + "`Options.TrustedOrigins`" + ` decides which browser origins and callback URLs may participate.
- ` + "`Options.Account.AccountLinking`" + ` controls implicit linking, unlinking, email ownership, and trusted providers.
- ` + "`Options.Account.EncryptOAuthTokens`" + ` encrypts persisted access and refresh tokens.
- ` + "`Options.Account.StoreStateStrategy`" + ` selects database or cookie-backed OAuth state.
- ` + "`Options.Account.SkipStateCookieCheck`" + ` weakens callback correlation and should only be used when the surrounding deployment supplies equivalent protection.
- Cookie settings determine whether OAuth state survives cross-site redirects and reverse proxies.

## HTTP client hardening

Use finite timeouts and reject redirects unless a provider explicitly requires them:

~~~go
providerHTTPClient := &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}
~~~

The low-level ` + "`oauth2`" + ` package includes redirect-refusing request helpers. Endpoint overrides remain application-controlled and must point to trusted HTTPS origins.
`

var customProviderPage = `---
title: "Custom provider"
---

Implement a server-side OAuth provider while retaining single-auth account and session behavior.

Use ` + "`providers.NewCustomProvider`" + ` when no built-in provider or Generic OAuth configuration represents the remote service correctly. The custom provider plugs into the same social sign-in, callback, account-linking, token, hook, and session lifecycle as a built-in.

## Required callbacks

` + "`ID`" + `, ` + "`CreateAuthorizationURL`" + `, ` + "`ValidateAuthorizationCode`" + `, and ` + "`GetUserInfo`" + ` are required. ` + "`Name`" + ` defaults to the ID. Refresh and ID-token verification callbacks are optional.

~~~go
const maxUserInfoBytes int64 = 1 << 20

clientID := os.Getenv("ACME_CLIENT_ID")
clientSecret := os.Getenv("ACME_CLIENT_SECRET")
providerHTTPClient := &http.Client{
    Timeout: 10 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}

custom, err := providers.NewCustomProvider(providers.CustomProvider{
    ID:   "acme",
    Name: "Acme Identity",
    Options: providers.Options{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        HTTPClient:   providerHTTPClient,
    },
    Metadata: providers.Metadata{
        AuthorizationEndpoint: "https://identity.acme.example/oauth/authorize",
        TokenEndpoint:         "https://identity.acme.example/oauth/token",
        UserInfoEndpoint:      "https://identity.acme.example/oauth/userinfo",
        DefaultScopes:         []string{"openid", "profile", "email"},
        TokenAuthentication:   oauth2.AuthenticationBasic,
    },
    CreateAuthorizationURL: func(input providers.AuthorizationInput) (*url.URL, error) {
        return oauth2.CreateAuthorizationURL(oauth2.AuthorizationURLOptions{
            AuthorizationEndpoint: "https://identity.acme.example/oauth/authorize",
            Options: oauth2.ProviderOptions{
                ClientID: clientID,
            },
            RedirectURI:           input.RedirectURI,
            State:                 input.State,
            Scopes:                append([]string{"openid", "profile", "email"}, input.Scopes...),
            CodeVerifier:          input.CodeVerifier,
        })
    },
    ValidateAuthorizationCode: func(ctx context.Context, input providers.CodeInput) (*oauth2.Tokens, error) {
        request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{
            Code:         input.Code,
            RedirectURI:  input.RedirectURI,
            CodeVerifier: input.CodeVerifier,
            Options: oauth2.ProviderOptions{
                ClientID:     clientID,
                ClientSecret: clientSecret,
            },
            Authentication: oauth2.AuthenticationBasic,
        })
        data, err := oauth2.DoForm(ctx, providerHTTPClient,
            "https://identity.acme.example/oauth/token", request)
        if err != nil {
            return nil, err
        }
        tokens := oauth2.NormalizeTokens(data, time.Now())
        return &tokens, nil
    },
    GetUserInfo: func(ctx context.Context, tokens oauth2.Tokens, _ *providers.AuthorizationUser) (*providers.UserInfoResult, error) {
        if tokens.AccessToken == "" {
            return nil, errors.New("acme user info: access token is empty")
        }
        request, err := http.NewRequestWithContext(ctx, http.MethodGet,
            "https://identity.acme.example/oauth/userinfo", nil)
        if err != nil {
            return nil, err
        }
        request.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
        request.Header.Set("Accept", "application/json")

        response, err := providerHTTPClient.Do(request)
        if err != nil {
            return nil, err
        }
        defer response.Body.Close()
        if response.StatusCode < 200 || response.StatusCode >= 300 {
            return nil, fmt.Errorf("acme user info: unexpected status %d", response.StatusCode)
        }
        mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
        if err != nil || mediaType != "application/json" {
            return nil, fmt.Errorf("acme user info: expected application/json")
        }

        payload, err := io.ReadAll(io.LimitReader(response.Body, maxUserInfoBytes+1))
        if err != nil {
            return nil, err
        }
        if int64(len(payload)) > maxUserInfoBytes {
            return nil, errors.New("acme user info: response exceeds 1 MiB")
        }
        var data map[string]any
        if err := json.Unmarshal(payload, &data); err != nil {
            return nil, fmt.Errorf("acme user info: decode data: %w", err)
        }
        subject, _ := data["sub"].(string)
        if subject == "" {
            return nil, errors.New("acme user info: sub is required")
        }
        name, _ := data["name"].(string)
        picture, _ := data["picture"].(string)
        emailVerified, _ := data["email_verified"].(bool)
        var email *string
        if value, ok := data["email"].(string); ok && value != "" {
            email = &value
        }
        return &providers.UserInfoResult{
            User: oauth2.UserInfo{
                ID:            subject,
                Name:          name,
                Email:         email,
                Image:         picture,
                EmailVerified: emailVerified,
                Extra:         map[string]any{},
            },
            Data: data,
        }, nil
    },
})
if err != nil {
    return err
}
~~~

The example uses a fixed HTTPS endpoint, a finite timeout, a redirect-refusing client, status/content-type checks, a 1 MiB response ceiling, and a required subject. Adjust the claim schema and email-verification rule to the remote provider's documented contract.

` + "`NewCustomProvider`" + ` derives ` + "`Metadata.SupportsRefresh`" + ` from the presence of ` + "`RefreshAccessToken`" + `. It does not derive ` + "`Metadata.SupportsIDToken`" + ` from ` + "`VerifyIDToken`" + `; set that metadata flag explicitly when the direct ID-token sign-in/link path should be available. The normal authorization-code callback still does not invoke the ID-token verifier automatically.

## Register it

~~~go
auth, err := singleauth.New(singleauth.Options{
    BaseURL: "https://auth.example.com",
    Secret:  os.Getenv("AUTH_SECRET"),
    SocialProviders: map[string]*providers.Provider{
        custom.ID: custom,
    },
})
~~~

The callback becomes ` + "`https://auth.example.com/api/auth/callback/acme`" + `. Provider IDs must be unique; plugin-factory registration also rejects collisions.

## Security contract

- Generate and validate cryptographically random state through the normal single-auth route lifecycle.
- Use PKCE for authorization-code flows whenever the remote provider supports it.
- Reject unexpected redirects, issuers, audiences, algorithms, content types, and oversized responses.
- Normalize a stable, provider-scoped subject into ` + "`UserInfo.ID`" + `.
- Set ` + "`EmailVerified`" + ` only from a cryptographically trustworthy claim or verified provider API response.
- Return remote claims in ` + "`Data`" + ` and application-specific normalized values in ` + "`User.Extra`" + ` without copying secrets.

If the service is a standard configurable OAuth/OIDC provider, prefer the [Generic OAuth plugin](../plugins/generic-oauth.md), which supplies discovery and route behavior without writing callback code.
`

func init() {
	sort.SliceStable(providerDocs, func(left, right int) bool {
		leftIndex := builtinIndex(providerDocs[left].ID)
		rightIndex := builtinIndex(providerDocs[right].ID)
		return leftIndex < rightIndex
	})
}

func builtinIndex(id string) int {
	for index, builtin := range providers.Builtins {
		if builtin == id {
			return index
		}
	}
	return len(providers.Builtins)
}
