package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func Discord(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "discord", name: "Discord", authorizationEndpoint: "https://discord.com/api/oauth2/authorize", tokenEndpoint: "https://discord.com/api/oauth2/token", userInfoEndpoint: "https://discord.com/api/users/@me",
		defaultScopes: []string{"identify", "email"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			scopes := combinedScopes(provider.Options, provider.Metadata.DefaultScopes, input.Scopes, true)
			prompt := provider.Options.Prompt
			if prompt == "" {
				prompt = "none"
			}
			raw := provider.Metadata.AuthorizationEndpoint + "?scope=" + strings.Join(scopes, "+") + "&response_type=code&client_id=" + primaryClientID(provider.Options.ClientID) + "&redirect_uri=" + encodeURIComponent(firstNonempty(provider.Options.RedirectURI, input.RedirectURI)) + "&state=" + input.State + "&prompt=" + prompt
			if contains(scopes, "bot") && provider.Options.Permissions != nil {
				raw += "&permissions=" + strconv.Itoa(*provider.Options.Permissions)
			}
			return url.Parse(raw)
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				avatar := stringValue(profile["avatar"])
				image := ""
				if profile["avatar"] == nil {
					image = discordDefaultAvatar(stringValue(profile["id"]), stringValue(profile["discriminator"]))
				} else {
					format := "png"
					if strings.HasPrefix(avatar, "a_") {
						format = "gif"
					}
					image = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", stringValue(profile["id"]), avatar, format)
				}
				profile["image_url"] = image
				name := stringValue(profile["global_name"])
				if name == "" {
					name = stringValue(profile["username"])
				}
				return result(ctx, provider, profile, stringValue(profile["id"]), name, profile["email"], image, boolValue(profile["verified"]))
			})
		},
	})
	return provider, nil
}

func Roblox(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "roblox", name: "Roblox", authorizationEndpoint: "https://apis.roblox.com/oauth/v1/authorize", tokenEndpoint: "https://apis.roblox.com/oauth/v1/token", userInfoEndpoint: "https://apis.roblox.com/oauth/v1/userinfo",
		defaultScopes: []string{"openid", "profile"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			scopes := combinedScopes(provider.Options, provider.Metadata.DefaultScopes, input.Scopes, false)
			prompt := provider.Options.Prompt
			if prompt == "" {
				prompt = "select_account consent"
			}
			return url.Parse(provider.Metadata.AuthorizationEndpoint + "?scope=" + strings.Join(scopes, "+") + "&response_type=code&client_id=" + primaryClientID(provider.Options.ClientID) + "&redirect_uri=" + encodeURIComponent(firstNonempty(provider.Options.RedirectURI, input.RedirectURI)) + "&state=" + input.State + "&prompt=" + encodeURIComponent(prompt))
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				name := stringValue(profile["nickname"])
				if name == "" {
					name = stringValue(profile["preferred_username"])
				}
				// The upstream intentionally puts preferred_username in email.
				return result(ctx, provider, profile, stringValue(profile["sub"]), name, nullableFallback(profile["preferred_username"]), stringValue(profile["picture"]), false)
			})
		},
	})
	return provider, nil
}

func Slack(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "slack", name: "Slack", authorizationEndpoint: "https://slack.com/openid/connect/authorize", tokenEndpoint: "https://slack.com/api/openid.connect.token", userInfoEndpoint: "https://slack.com/api/openid.connect.userInfo",
		defaultScopes: []string{"openid", "profile", "email"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			form := oauth2.NewForm()
			form.Set("scope", strings.Join(combinedScopes(provider.Options, provider.Metadata.DefaultScopes, input.Scopes, true), " "))
			form.Set("response_type", "code")
			form.Set("client_id", primaryClientID(provider.Options.ClientID))
			form.Set("redirect_uri", firstNonempty(provider.Options.RedirectURI, input.RedirectURI))
			form.Set("state", input.State)
			return url.Parse(provider.Metadata.AuthorizationEndpoint + "?" + form.Encode())
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				image := stringValue(profile["picture"])
				if image == "" {
					image = stringValue(profile["https://slack.com/user_image_512"])
				}
				return result(ctx, provider, profile, stringValue(profile["https://slack.com/user_id"]), stringValue(profile["name"]), profile["email"], image, boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func TikTok(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "tiktok", name: "TikTok", authorizationEndpoint: "https://www.tiktok.com/v2/auth/authorize", tokenEndpoint: "https://open.tiktokapis.com/v2/oauth/token/", userInfoEndpoint: "https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_large_url,display_name,username",
		defaultScopes: []string{"user.info.profile"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			scopes := combinedScopes(provider.Options, provider.Metadata.DefaultScopes, input.Scopes, false)
			return url.Parse(provider.Metadata.AuthorizationEndpoint + "?scope=" + strings.Join(scopes, ",") + "&response_type=code&client_key=" + provider.Options.ClientKey + "&redirect_uri=" + encodeURIComponent(firstNonempty(provider.Options.RedirectURI, input.RedirectURI)) + "&state=" + input.State)
		},
		validate: func(ctx context.Context, provider *Provider, input CodeInput) (*oauth2.Tokens, error) {
			options := oauth2.ProviderOptions{ClientSecret: provider.Options.ClientSecret, ClientKey: provider.Options.ClientKey, RedirectURI: provider.Options.RedirectURI}
			return exchange(ctx, provider, CodeInput{Code: input.Code, RedirectURI: input.RedirectURI}, oauth2.AuthenticationPost, withExchangeOptions(options))
		},
		refresh: func(ctx context.Context, provider *Provider, token string) (oauth2.Tokens, error) {
			return refresh(ctx, provider, token, oauth2.AuthenticationPost, oauth2.ProviderOptions{ClientSecret: provider.Options.ClientSecret}, oauth2.Param{Name: "client_key", Value: provider.Options.ClientKey})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, wrapper map[string]any) (*UserInfoResult, error) {
				profile := object(at(wrapper, "data", "user"))
				email := profile["email"]
				if stringValue(email) == "" {
					email = profile["username"]
				}
				name := stringValue(profile["display_name"])
				if name == "" {
					name = stringValue(profile["username"])
				}
				// the reference implementation 1.6.26 does not apply mapProfileToUser for TikTok.
				return &UserInfoResult{User: oauth2.UserInfo{ID: stringValue(profile["open_id"]), Name: name, Email: emailPointer(email), Image: stringValue(profile["avatar_large_url"]), EmailVerified: false, Extra: map[string]any{}}, Data: wrapper}, nil
			})
		},
	})
	return provider, nil
}

func WeChat(options Options) (*Provider, error) {
	provider := &Provider{ID: "wechat", Name: "WeChat", Options: options, Metadata: Metadata{AuthorizationEndpoint: "https://open.weixin.qq.com/connect/qrconnect", TokenEndpoint: "https://api.weixin.qq.com/sns/oauth2/access_token", UserInfoEndpoint: "https://api.weixin.qq.com/sns/userinfo", DefaultScopes: []string{"snsapi_login"}, SupportsRefresh: true}}
	provider.createAuthorizationURL = func(input AuthorizationInput) (*url.URL, error) {
		form := oauth2.NewForm()
		form.Set("scope", strings.Join(combinedScopes(options, provider.Metadata.DefaultScopes, input.Scopes, false), ","))
		form.Set("response_type", "code")
		form.Set("appid", primaryClientID(options.ClientID))
		form.Set("redirect_uri", firstNonempty(options.RedirectURI, input.RedirectURI))
		form.Set("state", input.State)
		lang := options.Language
		if lang == "" {
			lang = "cn"
		}
		form.Set("lang", lang)
		return url.Parse(provider.Metadata.AuthorizationEndpoint + "?" + form.Encode() + "#wechat_redirect")
	}
	wechatToken := func(ctx context.Context, endpoint string) (*oauth2.Tokens, error) {
		data := map[string]any{}
		if err := doJSON(ctx, provider.clientFor(ctx), http.MethodGet, endpoint, nil, nil, &data); err != nil {
			return nil, err
		}
		if stringValue(data["errcode"]) != "" && stringValue(data["errcode"]) != "0" {
			return nil, fmt.Errorf("%s", stringValue(data["errmsg"]))
		}
		tokens := oauth2.NormalizeTokens(data, time.Now())
		tokens.TokenType = "Bearer"
		if scope := stringValue(data["scope"]); scope != "" {
			tokens.Scopes = strings.Split(scope, ",")
		}
		return &tokens, nil
	}
	provider.validateCode = func(ctx context.Context, input CodeInput) (*oauth2.Tokens, error) {
		form := oauth2.NewForm()
		form.Set("appid", primaryClientID(options.ClientID))
		form.Set("secret", options.ClientSecret)
		form.Set("code", input.Code)
		form.Set("grant_type", "authorization_code")
		tokens, err := wechatToken(ctx, provider.Metadata.TokenEndpoint+"?"+form.Encode())
		if err != nil {
			return nil, fmt.Errorf("Failed to validate authorization code: %s", err.Error())
		}
		return tokens, nil
	}
	provider.refreshToken = func(ctx context.Context, token string) (oauth2.Tokens, error) {
		form := oauth2.NewForm()
		form.Set("appid", primaryClientID(options.ClientID))
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", token)
		tokens, err := wechatToken(ctx, "https://api.weixin.qq.com/sns/oauth2/refresh_token?"+form.Encode())
		if err != nil {
			return oauth2.Tokens{}, fmt.Errorf("Failed to refresh access token: %s", err.Error())
		}
		// the reference implementation's WeChat refresh path constructs a fresh token object and
		// does not expose the raw response. The initial exchange keeps Raw because
		// openid is required by getUserInfo.
		tokens.Raw = nil
		return *tokens, nil
	}
	provider.getUserInfo = func(ctx context.Context, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
		openid := stringValue(tokens.Raw["openid"])
		if openid == "" {
			return nil, nil
		}
		form := oauth2.NewForm()
		form.Set("access_token", tokens.AccessToken)
		form.Set("openid", openid)
		form.Set("lang", "zh_CN")
		profile, err := fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint+"?"+form.Encode(), nil, nil)
		if err != nil || (stringValue(profile["errcode"]) != "" && stringValue(profile["errcode"]) != "0") {
			return nil, nil
		}
		id := stringValue(profile["unionid"])
		if id == "" {
			id = stringValue(profile["openid"])
		}
		if id == "" {
			id = openid
		}
		email := profile["email"]
		if stringValue(email) == "" {
			email = id + "@wechat.invalid"
		}
		return result(ctx, provider, profile, id, stringValue(profile["nickname"]), email, stringValue(profile["headimgurl"]), false)
	}
	return provider, nil
}

func Zoom(options Options) (*Provider, error) {
	pkce := true
	if options.PKCE != nil {
		pkce = *options.PKCE
	}
	provider := newStandard(options, standardSpec{
		id: "zoom", name: "Zoom", authorizationEndpoint: "https://zoom.us/oauth/authorize", tokenEndpoint: "https://zoom.us/oauth/token", userInfoEndpoint: "https://api.zoom.us/v2/users/me",
		authentication: oauth2.AuthenticationPost,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			form := oauth2.NewForm()
			form.Set("response_type", "code")
			form.Set("redirect_uri", firstNonempty(provider.Options.RedirectURI, input.RedirectURI))
			form.Set("client_id", primaryClientID(provider.Options.ClientID))
			form.Set("state", input.State)
			if pkce {
				form.Set("code_challenge_method", "S256")
				form.Set("code_challenge", oauth2.GenerateCodeChallenge(input.CodeVerifier))
			}
			return url.Parse(provider.Metadata.AuthorizationEndpoint + "?" + form.Encode())
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				return result(ctx, provider, profile, stringValue(profile["id"]), stringValue(profile["display_name"]), profile["email"], stringValue(profile["pic_url"]), stringValue(profile["verified"]) != "" && stringValue(profile["verified"]) != "0")
			})
		},
	})
	return provider, nil
}

func Reddit(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "reddit", name: "Reddit", authorizationEndpoint: "https://www.reddit.com/api/v1/authorize", tokenEndpoint: "https://www.reddit.com/api/v1/access_token", userInfoEndpoint: "https://oauth.reddit.com/api/v1/me", defaultScopes: []string{"identity"}, authentication: oauth2.AuthenticationBasic,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.CodeVerifier = ""
				args.Duration = provider.Options.Duration
			})
		},
		validate: func(ctx context.Context, provider *Provider, input CodeInput) (*oauth2.Tokens, error) {
			request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{Code: input.Code, RedirectURI: input.RedirectURI, Options: providerOptions(provider.Options), Authentication: oauth2.AuthenticationBasic, Headers: map[string]string{"accept": "text/plain", "user-agent": "single-auth"}})
			data, err := doFormFollowingRedirects(ctx, provider.clientFor(ctx), provider.Metadata.TokenEndpoint, request)
			if err != nil {
				return nil, err
			}
			tokens := oauth2.NormalizeTokens(data, time.Now())
			return &tokens, nil
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			headers := bearer(tokens.AccessToken)
			headers["User-Agent"] = "single-auth"
			return resultOrNilOnFetchError(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, headers, nil, func(profile map[string]any) (*UserInfoResult, error) {
				mapped := map[string]any{}
				var err error
				if provider.Options.MapProfileToUser != nil {
					mapped, err = provider.Options.MapProfileToUser(ctx, profile)
					if err != nil {
						return nil, err
					}
				}
				email := mapped["email"]
				if stringValue(email) == "" {
					email = stringValue(profile["id"]) + "@reddit.invalid"
				}
				image := strings.Split(stringValue(profile["icon_img"]), "?")[0]
				user := oauth2.UserInfo{ID: stringValue(profile["id"]), Name: stringValue(profile["name"]), Email: emailPointer(email), Image: image, Extra: map[string]any{}}
				applyUserMap(&user, mapped)
				user.Email = emailPointer(email)
				if verified, exists := mapped["emailVerified"]; exists {
					user.EmailVerified = boolValue(verified)
				} else {
					user.EmailVerified = false
				}
				return &UserInfoResult{User: user, Data: profile}, nil
			})
		},
	})
	return provider, nil
}

func Notion(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "notion", name: "Notion", authorizationEndpoint: "https://api.notion.com/v1/oauth/authorize", tokenEndpoint: "https://api.notion.com/v1/oauth/token", userInfoEndpoint: "https://api.notion.com/v1/users/me", authentication: oauth2.AuthenticationBasic,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, []string{}, input, func(args *oauth2.AuthorizationURLOptions) {
				args.CodeVerifier = ""
				args.LoginHint = input.LoginHint
				args.AdditionalParams = []oauth2.Param{{Name: "owner", Value: "user"}}
			})
		},
		refresh: func(ctx context.Context, provider *Provider, token string) (oauth2.Tokens, error) {
			return refresh(ctx, provider, token, oauth2.AuthenticationPost, oauth2.ProviderOptions{ClientID: provider.Options.ClientID, ClientKey: provider.Options.ClientKey, ClientSecret: provider.Options.ClientSecret})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			headers := bearer(tokens.AccessToken)
			headers["Notion-Version"] = "2022-06-28"
			return resultOrNilOnFetchError(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, headers, nil, func(wrapper map[string]any) (*UserInfoResult, error) {
				profile := object(at(wrapper, "bot", "owner", "user"))
				if profile == nil {
					return nil, nil
				}
				return result(ctx, provider, profile, stringValue(profile["id"]), stringValue(profile["name"]), at(profile, "person", "email"), stringValue(profile["avatar_url"]), false)
			})
		},
	})
	return provider, nil
}

func Linear(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "linear", name: "Linear", authorizationEndpoint: "https://linear.app/oauth/authorize", tokenEndpoint: "https://api.linear.app/oauth/token", userInfoEndpoint: "https://api.linear.app/graphql", defaultScopes: []string{"read"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.CodeVerifier = ""
				args.LoginHint = input.LoginHint
			})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			const query = "\n\t\t\t\t\t\t\tquery {\n\t\t\t\t\t\t\t\tviewer {\n\t\t\t\t\t\t\t\t\tid\n\t\t\t\t\t\t\t\t\tname\n\t\t\t\t\t\t\t\t\temail\n\t\t\t\t\t\t\t\t\tavatarUrl\n\t\t\t\t\t\t\t\t\tactive\n\t\t\t\t\t\t\t\t\tcreatedAt\n\t\t\t\t\t\t\t\t\tupdatedAt\n\t\t\t\t\t\t\t\t}\n\t\t\t\t\t\t\t}\n\t\t\t\t\t\t"
			body, _ := json.Marshal(map[string]string{"query": query})
			headers := bearer(tokens.AccessToken)
			headers["Content-Type"] = "application/json"
			return resultOrNilOnFetchError(ctx, provider, http.MethodPost, provider.Metadata.UserInfoEndpoint, headers, bytes.NewReader(body), func(wrapper map[string]any) (*UserInfoResult, error) {
				profile := object(at(wrapper, "data", "viewer"))
				if profile == nil {
					return nil, nil
				}
				return result(ctx, provider, profile, stringValue(profile["id"]), stringValue(profile["name"]), profile["email"], stringValue(profile["avatarUrl"]), false)
			})
		},
	})
	return provider, nil
}

func VK(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "vk", name: "VK", authorizationEndpoint: "https://id.vk.com/authorize", tokenEndpoint: "https://id.vk.com/oauth2/auth", userInfoEndpoint: "https://id.vk.com/oauth2/user_info", defaultScopes: []string{"email", "phone"},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			if tokens.AccessToken == "" {
				return nil, nil
			}
			form := oauth2.NewForm()
			form.Set("access_token", tokens.AccessToken)
			form.Set("client_id", primaryClientID(provider.Options.ClientID))
			headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			return resultOrNilOnFetchError(ctx, provider, http.MethodPost, provider.Metadata.UserInfoEndpoint, headers, strings.NewReader(form.Encode()), func(profile map[string]any) (*UserInfoResult, error) {
				userProfile := object(profile["user"])
				mapped := map[string]any{}
				var err error
				if provider.Options.MapProfileToUser != nil {
					mapped, err = provider.Options.MapProfileToUser(ctx, profile)
					if err != nil {
						return nil, err
					}
				}
				if stringValue(userProfile["email"]) == "" && stringValue(mapped["email"]) == "" {
					return nil, nil
				}
				name := strings.TrimSpace(stringValue(userProfile["first_name"]) + " " + stringValue(userProfile["last_name"]))
				user := oauth2.UserInfo{ID: stringValue(userProfile["user_id"]), Name: name, Email: emailPointer(userProfile["email"]), Image: stringValue(userProfile["avatar"]), Extra: map[string]any{"first_name": userProfile["first_name"], "last_name": userProfile["last_name"], "birthday": userProfile["birthday"], "sex": userProfile["sex"]}}
				applyUserMap(&user, mapped)
				return &UserInfoResult{User: user, Data: profile}, nil
			})
		},
	})
	return provider, nil
}

func Twitch(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "twitch", name: "Twitch", authorizationEndpoint: "https://id.twitch.tv/oauth2/authorize", tokenEndpoint: "https://id.twitch.tv/oauth2/token", defaultScopes: []string{"user:read:email", "openid"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			claims := provider.Options.Claims
			if claims == nil {
				claims = []string{"email", "email_verified", "preferred_username", "picture"}
			}
			filtered := make([]string, 0, len(claims))
			for _, claim := range claims {
				if claim != "email" && claim != "email_verified" {
					filtered = append(filtered, claim)
				}
			}
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) { args.CodeVerifier = ""; args.Claims = filtered })
		},
		profile: jwtProfile(func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
			return result(ctx, provider, profile, stringValue(profile["sub"]), stringValue(profile["preferred_username"]), profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
		}),
	})
	return provider, nil
}

func Twitter(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "twitter", name: "Twitter", authorizationEndpoint: "https://x.com/i/oauth2/authorize", tokenEndpoint: "https://api.x.com/2/oauth2/token", userInfoEndpoint: "https://api.x.com/2/users/me?user.fields=profile_image_url", defaultScopes: []string{"users.read", "tweet.read", "offline.access", "users.email"}, authentication: oauth2.AuthenticationBasic,
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			profile, err := fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, bearer(tokens.AccessToken), nil)
			if err != nil {
				return nil, nil
			}
			data := object(profile["data"])
			verified := false
			emailWrapper, emailErr := fetchProfile(ctx, provider, http.MethodGet, "https://api.x.com/2/users/me?user.fields=confirmed_email", bearer(tokens.AccessToken), nil)
			if emailErr == nil {
				email := stringValue(at(emailWrapper, "data", "confirmed_email"))
				if email != "" {
					data["email"] = email
					verified = true
				}
			}
			email := data["email"]
			if stringValue(email) == "" {
				email = data["username"]
			}
			return result(ctx, provider, profile, stringValue(data["id"]), stringValue(data["name"]), nullableFallback(email), stringValue(data["profile_image_url"]), verified)
		},
	})
	return provider, nil
}

func GitHub(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "github", name: "GitHub", authorizationEndpoint: "https://github.com/login/oauth/authorize", tokenEndpoint: "https://github.com/login/oauth/access_token", userInfoEndpoint: "https://api.github.com/user", defaultScopes: []string{"read:user", "user:email"},
		authorize: promptAuthorization,
		validate: func(ctx context.Context, provider *Provider, input CodeInput) (*oauth2.Tokens, error) {
			request := oauth2.CreateAuthorizationCodeRequest(oauth2.AuthorizationCodeRequestOptions{Code: input.Code, CodeVerifier: input.CodeVerifier, RedirectURI: input.RedirectURI, Options: providerOptions(provider.Options)})
			data, err := doFormFollowingRedirects(ctx, provider.clientFor(ctx), provider.Metadata.TokenEndpoint, request)
			if err != nil {
				return nil, nil
			}
			if stringValue(data["error"]) != "" {
				return nil, nil
			}
			tokens := oauth2.NormalizeTokens(data, time.Now())
			return &tokens, nil
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			headers := bearer(tokens.AccessToken)
			headers["User-Agent"] = "single-auth"
			profile, err := fetchProfile(ctx, provider, http.MethodGet, provider.Metadata.UserInfoEndpoint, headers, nil)
			if err != nil {
				return nil, nil
			}
			var emails []any
			_ = doJSON(ctx, provider.clientFor(ctx), http.MethodGet, "https://api.github.com/user/emails", headers, nil, &emails)
			if stringValue(profile["email"]) == "" {
				for _, item := range emails {
					email := object(item)
					if boolValue(email["primary"]) {
						profile["email"] = email["email"]
						break
					}
				}
				if stringValue(profile["email"]) == "" && len(emails) != 0 {
					profile["email"] = object(emails[0])["email"]
				}
			}
			verified := false
			for _, item := range emails {
				email := object(item)
				if stringValue(email["email"]) == stringValue(profile["email"]) {
					verified = boolValue(email["verified"])
					break
				}
			}
			name := stringValue(profile["name"])
			if name == "" {
				name = stringValue(profile["login"])
			}
			return result(ctx, provider, profile, stringValue(profile["id"]), name, profile["email"], stringValue(profile["avatar_url"]), verified)
		},
	})
	return provider, nil
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func nullableFallback(value any) any {
	if stringValue(value) == "" {
		return nil
	}
	return value
}
