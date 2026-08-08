package providers

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

func Spotify(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "spotify", name: "Spotify",
		authorizationEndpoint: "https://accounts.spotify.com/authorize",
		tokenEndpoint:         "https://accounts.spotify.com/api/token",
		userInfoEndpoint:      "https://api.spotify.com/v1/me",
		defaultScopes:         []string{"user-read-email"},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				image := ""
				images := array(profile["images"])
				if len(images) != 0 {
					image = stringValue(at(object(images[0]), "url"))
				}
				return result(ctx, provider, profile, stringValue(profile["id"]), stringValue(profile["display_name"]), profile["email"], image, false)
			})
		},
	})
	return provider, nil
}

func Railway(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "railway", name: "Railway",
		authorizationEndpoint: "https://backboard.railway.com/oauth/auth",
		tokenEndpoint:         "https://backboard.railway.com/oauth/token",
		userInfoEndpoint:      "https://backboard.railway.com/oauth/me",
		defaultScopes:         []string{"openid", "email", "profile"},
		authentication:        oauth2.AuthenticationBasic,
		profile:               simpleProfile("sub", []string{"name"}, []string{"email"}, []string{"picture"}, nil),
	})
	return provider, nil
}

func LinkedIn(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "linkedin", name: "Linkedin",
		authorizationEndpoint: "https://www.linkedin.com/oauth/v2/authorization",
		tokenEndpoint:         "https://www.linkedin.com/oauth/v2/accessToken",
		userInfoEndpoint:      "https://api.linkedin.com/v2/userinfo",
		defaultScopes:         []string{"profile", "email", "openid"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.CodeVerifier = ""
				args.LoginHint = input.LoginHint
			})
		},
		profile: simpleProfile("sub", []string{"name"}, []string{"email"}, []string{"picture"}, []string{"email_verified"}),
	})
	return provider, nil
}

func HuggingFace(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "huggingface", name: "Hugging Face",
		authorizationEndpoint: "https://huggingface.co/oauth/authorize",
		tokenEndpoint:         "https://huggingface.co/oauth/token",
		userInfoEndpoint:      "https://huggingface.co/oauth/userinfo",
		defaultScopes:         []string{"openid", "profile", "email"},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				name := stringValue(profile["name"])
				if name == "" {
					name = stringValue(profile["preferred_username"])
				}
				return result(ctx, provider, profile, stringValue(profile["sub"]), name, profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func GitLab(options Options) (*Provider, error) {
	base := options.Issuer
	if base == "" {
		base = "https://gitlab.com"
	}
	clean := func(value string) string {
		parts := strings.Split(value, "://")
		for index := range parts {
			for strings.Contains(parts[index], "//") {
				parts[index] = strings.ReplaceAll(parts[index], "//", "/")
			}
		}
		return strings.Join(parts, "://")
	}
	provider := newStandard(options, standardSpec{
		id: "gitlab", name: "Gitlab",
		authorizationEndpoint: clean(base + "/oauth/authorize"),
		tokenEndpoint:         clean(base + "/oauth/token"),
		userInfoEndpoint:      clean(base + "/api/v4/user"),
		defaultScopes:         []string{"read_user"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) { args.LoginHint = input.LoginHint })
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				if stringValue(profile["state"]) != "active" || boolValue(profile["locked"]) {
					return nil, nil
				}
				name := stringValue(profile["name"])
				if name == "" {
					name = stringValue(profile["username"])
				}
				return result(ctx, provider, profile, stringValue(profile["id"]), name, profile["email"], stringValue(profile["avatar_url"]), boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func Naver(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "naver", name: "Naver",
		authorizationEndpoint: "https://nid.naver.com/oauth2.0/authorize",
		tokenEndpoint:         "https://nid.naver.com/oauth2.0/token",
		userInfoEndpoint:      "https://openapi.naver.com/v1/nid/me",
		defaultScopes:         []string{"profile", "email"},
		authorize:             withoutPKCEAuthorization,
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				if stringValue(profile["resultcode"]) != "00" {
					return nil, nil
				}
				response := object(profile["response"])
				name := stringValue(response["name"])
				if name == "" {
					name = stringValue(response["nickname"])
				}
				return result(ctx, provider, profile, stringValue(response["id"]), name, response["email"], stringValue(response["profile_image"]), false)
			})
		},
	})
	return provider, nil
}

func Kakao(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "kakao", name: "Kakao",
		authorizationEndpoint: "https://kauth.kakao.com/oauth/authorize",
		tokenEndpoint:         "https://kauth.kakao.com/oauth/token",
		userInfoEndpoint:      "https://kapi.kakao.com/v2/user/me",
		defaultScopes:         []string{"account_email", "profile_image", "profile_nickname"},
		authorize:             withoutPKCEAuthorization,
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				account := object(profile["kakao_account"])
				kp := object(account["profile"])
				name := stringValue(kp["nickname"])
				if name == "" {
					name = stringValue(account["name"])
				}
				image := stringValue(kp["profile_image_url"])
				if image == "" {
					image = stringValue(kp["thumbnail_image_url"])
				}
				verified := boolValue(account["is_email_valid"]) && boolValue(account["is_email_verified"])
				return result(ctx, provider, profile, stringValue(profile["id"]), name, account["email"], image, verified)
			})
		},
	})
	return provider, nil
}

func Dropbox(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "dropbox", name: "Dropbox",
		authorizationEndpoint: "https://www.dropbox.com/oauth2/authorize",
		tokenEndpoint:         "https://api.dropboxapi.com/oauth2/token",
		userInfoEndpoint:      "https://api.dropboxapi.com/2/users/get_current_account",
		defaultScopes:         []string{"account_info.read"},
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				if provider.Options.AccessType != "" {
					args.AdditionalParams = []oauth2.Param{{Name: "token_access_type", Value: provider.Options.AccessType}}
				}
			})
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return resultOrNilOnFetchError(ctx, provider, http.MethodPost, provider.Metadata.UserInfoEndpoint, bearer(tokens.AccessToken), nil, func(profile map[string]any) (*UserInfoResult, error) {
				return result(ctx, provider, profile, stringValue(profile["account_id"]), stringValue(at(profile, "name", "display_name")), profile["email"], stringValue(profile["profile_photo_url"]), boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func Figma(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "figma", name: "Figma",
		authorizationEndpoint: "https://www.figma.com/oauth",
		tokenEndpoint:         "https://api.figma.com/v1/oauth/token",
		userInfoEndpoint:      "https://api.figma.com/v1/me",
		defaultScopes:         []string{"current_user:read"},
		authentication:        oauth2.AuthenticationBasic,
		requireCredentials:    true, requireCodeVerifier: true,
		profile: simpleProfile("id", []string{"handle"}, []string{"email"}, []string{"img_url"}, nil),
	})
	return provider, nil
}

func Atlassian(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "atlassian", name: "Atlassian",
		authorizationEndpoint: "https://auth.atlassian.com/authorize",
		tokenEndpoint:         "https://auth.atlassian.com/oauth/token",
		userInfoEndpoint:      "https://api.atlassian.com/me",
		defaultScopes:         []string{"read:jira-user", "offline_access"},
		requireCredentials:    true, requireCodeVerifier: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.AdditionalParams = []oauth2.Param{{Name: "audience", Value: "api.atlassian.com"}}
				args.Prompt = provider.Options.Prompt
			})
		},
		profile: simpleProfile("account_id", []string{"name"}, []string{"email"}, []string{"picture"}, nil),
	})
	return provider, nil
}

func Salesforce(options Options) (*Provider, error) {
	host := "login.salesforce.com"
	if options.Environment == "sandbox" {
		host = "test.salesforce.com"
	}
	if options.LoginURL != "" {
		host = options.LoginURL
	}
	base := "https://" + host + "/services/oauth2/"
	provider := newStandard(options, standardSpec{
		id: "salesforce", name: "Salesforce",
		authorizationEndpoint: base + "authorize", tokenEndpoint: base + "token", userInfoEndpoint: base + "userinfo",
		defaultScopes:      []string{"openid", "email", "profile"},
		requireCredentials: true, requireCodeVerifier: true,
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				image := stringValue(at(profile, "photos", "picture"))
				if image == "" {
					image = stringValue(at(profile, "photos", "thumbnail"))
				}
				return result(ctx, provider, profile, stringValue(profile["user_id"]), stringValue(profile["name"]), profile["email"], image, boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func Vercel(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "vercel", name: "Vercel",
		authorizationEndpoint: "https://vercel.com/oauth/authorize", tokenEndpoint: "https://api.vercel.com/login/oauth/token", userInfoEndpoint: "https://api.vercel.com/login/oauth/userinfo",
		defaultScopes: nil, requireCodeVerifier: true, noRefresh: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			var scopes []string
			if provider.Options.Scopes != nil || input.Scopes != nil {
				scopes = append(cloneStrings(provider.Options.Scopes), input.Scopes...)
			}
			args := oauth2.AuthorizationURLOptions{ID: provider.ID, Options: providerOptions(provider.Options), AuthorizationEndpoint: provider.Metadata.AuthorizationEndpoint, RedirectURI: input.RedirectURI, State: input.State, CodeVerifier: input.CodeVerifier, Scopes: scopes}
			return oauth2.CreateAuthorizationURL(args)
		},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
				name := stringValue(profile["name"])
				if name == "" {
					name = stringValue(profile["preferred_username"])
				}
				return result(ctx, provider, profile, stringValue(profile["sub"]), name, profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
			})
		},
	})
	return provider, nil
}

func Paybin(options Options) (*Provider, error) {
	issuer := options.Issuer
	if issuer == "" {
		issuer = "https://idp.paybin.io"
	}
	provider := newStandard(options, standardSpec{
		id: "paybin", name: "Paybin", authorizationEndpoint: issuer + "/oauth2/authorize", tokenEndpoint: issuer + "/oauth2/token",
		defaultScopes: []string{"openid", "email", "profile"}, requireCredentials: true, requireCodeVerifier: true,
		authorize: func(provider *Provider, input AuthorizationInput) (*url.URL, error) {
			return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
				args.Prompt = provider.Options.Prompt
				args.LoginHint = input.LoginHint
			})
		},
		profile: jwtProfile(func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
			name := stringValue(profile["name"])
			if name == "" {
				name = stringValue(profile["preferred_username"])
			}
			return result(ctx, provider, profile, stringValue(profile["sub"]), name, profile["email"], stringValue(profile["picture"]), boolValue(profile["email_verified"]))
		}),
	})
	return provider, nil
}

func Kick(options Options) (*Provider, error) {
	provider := newStandard(options, standardSpec{
		id: "kick", name: "Kick", authorizationEndpoint: "https://id.kick.com/oauth/authorize", tokenEndpoint: "https://id.kick.com/oauth/token", userInfoEndpoint: "https://api.kick.com/public/v1/users",
		defaultScopes: []string{"user:read"},
		profile: func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
			return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, wrapper map[string]any) (*UserInfoResult, error) {
				profiles := array(wrapper["data"])
				if len(profiles) == 0 {
					return nil, errorsInternal("Kick user response has no users")
				}
				profile := object(profiles[0])
				return result(ctx, provider, profile, stringValue(profile["user_id"]), stringValue(profile["name"]), profile["email"], stringValue(profile["profile_picture"]), false)
			})
		},
	})
	return provider, nil
}

func promptAuthorization(provider *Provider, input AuthorizationInput) (*url.URL, error) {
	return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) {
		args.Prompt = provider.Options.Prompt
		if provider.ID == "github" {
			args.LoginHint = input.LoginHint
		}
	})
}

func withoutPKCEAuthorization(provider *Provider, input AuthorizationInput) (*url.URL, error) {
	return createURL(provider.ID, provider.Options, provider.Metadata.AuthorizationEndpoint, provider.Metadata.DefaultScopes, input, func(args *oauth2.AuthorizationURLOptions) { args.CodeVerifier = "" })
}

func simpleProfile(idKey string, namePath, emailPath, imagePath, verifiedPath []string) profileGetter {
	return func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
		return getBearerProfile(ctx, provider, tokens, provider.Metadata.UserInfoEndpoint, func(ctx context.Context, provider *Provider, profile map[string]any) (*UserInfoResult, error) {
			var name, image string
			var email any
			verified := false
			if len(namePath) != 0 {
				name = stringValue(at(profile, namePath...))
			}
			if len(emailPath) != 0 {
				email = at(profile, emailPath...)
			}
			if len(imagePath) != 0 {
				image = stringValue(at(profile, imagePath...))
			}
			if len(verifiedPath) != 0 {
				verified = boolValue(at(profile, verifiedPath...))
			}
			return result(ctx, provider, profile, stringValue(profile[idKey]), name, email, image, verified)
		})
	}
}

func jwtProfile(mapper func(context.Context, *Provider, map[string]any) (*UserInfoResult, error)) profileGetter {
	return func(ctx context.Context, provider *Provider, tokens oauth2.Tokens, _ *AuthorizationUser) (*UserInfoResult, error) {
		if tokens.IDToken == "" {
			return nil, nil
		}
		profile, err := decodeJWT(tokens.IDToken)
		if err != nil {
			return nil, nil
		}
		return mapper(ctx, provider, profile)
	}
}
