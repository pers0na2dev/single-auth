package genericoauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

// BaseOAuthProviderOptions is the shared option set accepted by the provider
// helpers. ClientSecret is required by the upstream helpers and is retained as
// a concrete string in Go.
type BaseOAuthProviderOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool

	DisableImplicitSignUp bool
	DisableSignUp         bool
	OverrideUserInfo      bool
	HTTPClient            *http.Client
}

type Auth0Options struct {
	BaseOAuthProviderOptions
	Domain string
}

func Auth0(options Auth0Options) Config {
	domain := strings.TrimPrefix(strings.TrimPrefix(options.Domain, "https://"), "http://")
	return withBase(Config{
		ProviderID:   "auth0",
		DiscoveryURL: "https://" + domain + "/.well-known/openid-configuration",
	}, options.BaseOAuthProviderOptions, []string{"openid", "profile", "email"})
}

type OktaOptions struct {
	BaseOAuthProviderOptions
	Issuer string
}

func Okta(options OktaOptions) Config {
	issuer := strings.TrimSuffix(options.Issuer, "/")
	return withBase(Config{
		ProviderID:   "okta",
		DiscoveryURL: issuer + "/.well-known/openid-configuration",
	}, options.BaseOAuthProviderOptions, []string{"openid", "profile", "email"})
}

type KeycloakOptions struct {
	BaseOAuthProviderOptions
	Issuer string
}

func Keycloak(options KeycloakOptions) Config {
	issuer := strings.TrimSuffix(options.Issuer, "/")
	return withBase(Config{
		ProviderID:   "keycloak",
		DiscoveryURL: issuer + "/.well-known/openid-configuration",
	}, options.BaseOAuthProviderOptions, []string{"openid", "profile", "email"})
}

type MicrosoftEntraIDOptions struct {
	BaseOAuthProviderOptions
	TenantID string
}

func MicrosoftEntraID(options MicrosoftEntraIDOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "microsoft-entra-id",
		AuthorizationURL: "https://login.microsoftonline.com/" + options.TenantID + "/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/" + options.TenantID + "/oauth2/v2.0/token",
		UserInfoURL:      "https://graph.microsoft.com/oidc/userinfo",
	}, base, []string{"openid", "profile", "email"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		profile, err := helperProfile(ctx, base.HTTPClient, config.UserInfoURL, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
		if err != nil || profile == nil {
			return nil, nil
		}
		name := stringValue(profile["name"])
		if name == "" {
			name = strings.TrimSpace(stringValue(profile["given_name"]) + " " + stringValue(profile["family_name"]))
		}
		email := stringValue(profile["email"])
		if email == "" {
			email = stringValue(profile["preferred_username"])
		}
		return Profile{
			"id": profile["sub"], "name": name, "email": email,
			"image":         stringValue(profile["picture"]),
			"emailVerified": boolValue(profile["email_verified"]),
		}, nil
	}
	return config
}

type SlackOptions struct{ BaseOAuthProviderOptions }

func Slack(options SlackOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "slack",
		AuthorizationURL: "https://slack.com/openid/connect/authorize",
		TokenURL:         "https://slack.com/api/openid.connect.token",
		UserInfoURL:      "https://slack.com/api/openid.connect.userInfo",
	}, base, []string{"openid", "profile", "email"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		profile, err := helperProfile(ctx, base.HTTPClient, config.UserInfoURL, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
		if err != nil || profile == nil {
			return nil, nil
		}
		id := profile["https://slack.com/user_id"]
		if !nonEmptyID(id) {
			id = profile["sub"]
		}
		image := stringValue(profile["picture"])
		if image == "" {
			image = stringValue(profile["https://slack.com/user_image_512"])
		}
		return Profile{
			"id": id, "name": stringValue(profile["name"]),
			"email": stringValue(profile["email"]), "image": image,
			"emailVerified": boolValue(profile["email_verified"]),
		}, nil
	}
	return config
}

type GumroadOptions struct{ BaseOAuthProviderOptions }

func Gumroad(options GumroadOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "gumroad",
		AuthorizationURL: "https://gumroad.com/oauth/authorize",
		TokenURL:         "https://api.gumroad.com/oauth/token",
	}, base, []string{"view_profile"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		wrapper, err := helperProfile(ctx, base.HTTPClient, "https://api.gumroad.com/v2/user", map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
		if err != nil || wrapper == nil || !boolValue(wrapper["success"]) {
			return nil, nil
		}
		user := profileObject(wrapper["user"])
		if user == nil {
			return nil, nil
		}
		return Profile{
			"id": user["user_id"], "name": stringValue(user["name"]),
			"email": stringValue(user["email"]), "image": stringValue(user["profile_url"]),
			"emailVerified": false,
		}, nil
	}
	return config
}

type HubSpotOptions struct{ BaseOAuthProviderOptions }

func HubSpot(options HubSpotOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "hubspot",
		AuthorizationURL: "https://app.hubspot.com/oauth/authorize",
		TokenURL:         "https://api.hubapi.com/oauth/v1/token",
		Authentication:   oauth2.AuthenticationPost,
	}, base, []string{"oauth"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		endpoint := "https://api.hubapi.com/oauth/v1/access-tokens/" + tokens.AccessToken
		profile, err := helperProfile(ctx, base.HTTPClient, endpoint, map[string]string{"Content-Type": "application/json"})
		if err != nil || profile == nil {
			return nil, nil
		}
		id := profile["user_id"]
		if !nonEmptyID(id) {
			id = profileObject(profile["signed_access_token"])["userId"]
		}
		if !nonEmptyID(id) {
			return nil, nil
		}
		return Profile{
			"id": id, "name": stringValue(profile["user"]),
			"email": stringValue(profile["user"]), "emailVerified": false,
		}, nil
	}
	return config
}

type LineOptions struct {
	BaseOAuthProviderOptions
	ProviderID string
}

func Line(options LineOptions) Config {
	base := options.BaseOAuthProviderOptions
	providerID := options.ProviderID
	if providerID == "" {
		providerID = "line"
	}
	config := withBase(Config{
		ProviderID:       providerID,
		AuthorizationURL: "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:         "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:      "https://api.line.me/oauth2/v2.1/userinfo",
	}, base, []string{"openid", "profile", "email"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		var profile Profile
		if tokens.IDToken != "" {
			decoded, err := decodeJWTPayload(tokens.IDToken)
			if err == nil {
				profile = decoded
			}
		}
		if profile == nil {
			var err error
			profile, err = helperProfile(ctx, base.HTTPClient, config.UserInfoURL, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
			if err != nil || profile == nil {
				return nil, nil
			}
		}
		return Profile{
			"id": profile["sub"], "name": stringValue(profile["name"]),
			"email": stringValue(profile["email"]), "image": stringValue(profile["picture"]),
			"emailVerified": false,
		}, nil
	}
	return config
}

type PatreonOptions struct{ BaseOAuthProviderOptions }

func Patreon(options PatreonOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "patreon",
		AuthorizationURL: "https://www.patreon.com/oauth2/authorize",
		TokenURL:         "https://www.patreon.com/api/oauth2/token",
	}, base, []string{"identity[email]"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		endpoint := "https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url,is_email_verified"
		wrapper, err := helperProfile(ctx, base.HTTPClient, endpoint, map[string]string{"Authorization": "Bearer " + tokens.AccessToken})
		if err != nil || wrapper == nil {
			return nil, nil
		}
		data := profileObject(wrapper["data"])
		attributes := profileObject(data["attributes"])
		if data == nil || attributes == nil {
			return nil, nil
		}
		return Profile{
			"id": data["id"], "name": stringValue(attributes["full_name"]),
			"email": stringValue(attributes["email"]), "image": stringValue(attributes["image_url"]),
			"emailVerified": boolValue(attributes["is_email_verified"]),
		}, nil
	}
	return config
}

type YandexOptions struct{ BaseOAuthProviderOptions }

func Yandex(options YandexOptions) Config {
	base := options.BaseOAuthProviderOptions
	config := withBase(Config{
		ProviderID:       "yandex",
		AuthorizationURL: "https://oauth.yandex.com/authorize",
		TokenURL:         "https://oauth.yandex.com/token",
	}, base, []string{"login:info", "login:email", "login:avatar"})
	config.GetUserInfo = func(ctx context.Context, tokens oauth2.Tokens) (Profile, error) {
		profile, err := helperProfile(ctx, base.HTTPClient, "https://login.yandex.ru/info?format=json", map[string]string{"Authorization": "OAuth " + tokens.AccessToken})
		if err != nil || profile == nil {
			return nil, nil
		}
		name := firstNonEmpty(profile, "display_name", "real_name", "first_name", "login")
		email := stringValue(profile["default_email"])
		if email == "" {
			email = firstString(profile["emails"])
		}
		image := ""
		if !boolValue(profile["is_avatar_empty"]) && stringValue(profile["default_avatar_id"]) != "" {
			image = "https://avatars.yandex.net/get-yapic/" + stringValue(profile["default_avatar_id"]) + "/islands-200"
		}
		return Profile{
			"id": profile["id"], "name": name, "email": email,
			"image": image, "emailVerified": false,
		}, nil
	}
	return config
}

func withBase(config Config, options BaseOAuthProviderOptions, defaults []string) Config {
	config.ClientID = options.ClientID
	config.ClientSecret = options.ClientSecret
	config.Scopes = append([]string(nil), defaults...)
	if options.Scopes != nil {
		config.Scopes = append([]string(nil), options.Scopes...)
	}
	config.RedirectURI = options.RedirectURI
	config.PKCE = options.PKCE
	config.DisableImplicitSignUp = options.DisableImplicitSignUp
	config.DisableSignUp = options.DisableSignUp
	config.OverrideUserInfo = options.OverrideUserInfo
	config.HTTPClient = options.HTTPClient
	return config
}

func helperProfile(ctx context.Context, client *http.Client, endpoint string, headers map[string]string) (Profile, error) {
	profile := Profile{}
	if err := fetchJSON(ctx, client, endpoint, headers, &profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func profileObject(value any) Profile {
	if value == nil {
		return nil
	}
	if profile, ok := value.(Profile); ok {
		return profile
	}
	if profile, ok := value.(map[string]any); ok {
		return Profile(profile)
	}
	return nil
}

func firstNonEmpty(profile Profile, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(profile[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstString(value any) string {
	switch list := value.(type) {
	case []any:
		if len(list) != 0 {
			return stringValue(list[0])
		}
	case []string:
		if len(list) != 0 {
			return list[0]
		}
	}
	return ""
}

// ProviderCallbackURL returns the default callback URI used by helper-based
// generic providers. It is exported for configuration diagnostics.
func ProviderCallbackURL(baseURL, providerID string) (string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("genericoauth: invalid base URL %q", baseURL)
	}
	return strings.TrimRight(baseURL, "/") + "/oauth2/callback/" + url.PathEscape(providerID), nil
}
