package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

type authorizationBuilder func(*Provider, AuthorizationInput) (*url.URL, error)
type codeValidator func(context.Context, *Provider, CodeInput) (*oauth2.Tokens, error)
type profileGetter func(context.Context, *Provider, oauth2.Tokens, *AuthorizationUser) (*UserInfoResult, error)

type standardSpec struct {
	id                    string
	name                  string
	authorizationEndpoint string
	tokenEndpoint         string
	userInfoEndpoint      string
	defaultScopes         []string
	authentication        oauth2.Authentication
	requireCredentials    bool
	requireCodeVerifier   bool
	authorize             authorizationBuilder
	validate              codeValidator
	profile               profileGetter
	refresh               func(context.Context, *Provider, string) (oauth2.Tokens, error)
	noRefresh             bool
}

func newStandard(options Options, spec standardSpec) *Provider {
	provider := &Provider{
		ID:      spec.id,
		Name:    spec.name,
		Options: options,
		Metadata: Metadata{
			AuthorizationEndpoint: spec.authorizationEndpoint,
			TokenEndpoint:         spec.tokenEndpoint,
			UserInfoEndpoint:      spec.userInfoEndpoint,
			DefaultScopes:         cloneStrings(spec.defaultScopes),
			TokenAuthentication:   spec.authentication,
			SupportsRefresh:       !spec.noRefresh,
		},
	}
	provider.createAuthorizationURL = func(input AuthorizationInput) (*url.URL, error) {
		if spec.requireCredentials && (primaryClientID(options.ClientID) == "" || options.ClientSecret == "") {
			return nil, ErrClientIDAndSecretRequired
		}
		if spec.requireCodeVerifier && input.CodeVerifier == "" {
			return nil, fmt.Errorf("%w for %s", ErrCodeVerifierRequired, spec.name)
		}
		if spec.authorize != nil {
			return spec.authorize(provider, input)
		}
		return createURL(spec.id, options, spec.authorizationEndpoint, spec.defaultScopes, input, nil)
	}
	provider.validateCode = func(ctx context.Context, input CodeInput) (*oauth2.Tokens, error) {
		if spec.validate != nil {
			return spec.validate(ctx, provider, input)
		}
		exchangeInput := CodeInput{Code: input.Code, RedirectURI: input.RedirectURI}
		if providerUsesCodeVerifier(spec.id) {
			exchangeInput.CodeVerifier = input.CodeVerifier
		}
		if spec.id == "vk" {
			exchangeInput.DeviceID = input.DeviceID
		}
		return exchange(ctx, provider, exchangeInput, spec.authentication)
	}
	if !spec.noRefresh {
		provider.refreshToken = func(ctx context.Context, token string) (oauth2.Tokens, error) {
			if spec.refresh != nil {
				return spec.refresh(ctx, provider, token)
			}
			return defaultRefresh(provider, spec.authentication)(ctx, token)
		}
	}
	provider.getUserInfo = func(ctx context.Context, tokens oauth2.Tokens, user *AuthorizationUser) (*UserInfoResult, error) {
		if spec.profile != nil {
			return spec.profile(ctx, provider, tokens, user)
		}
		return nil, nil
	}
	return provider
}

func providerUsesCodeVerifier(id string) bool {
	switch id {
	case "apple", "atlassian", "cognito", "figma", "github", "microsoft", "google", "huggingface", "spotify", "twitter", "dropbox", "kick", "gitlab", "salesforce", "vk", "zoom", "line", "paybin", "railway", "vercel":
		return true
	default:
		return false
	}
}

func getBearerProfile(ctx context.Context, provider *Provider, tokens oauth2.Tokens, endpoint string, mapper func(context.Context, *Provider, map[string]any) (*UserInfoResult, error)) (*UserInfoResult, error) {
	if tokens.AccessToken == "" {
		return nil, nil
	}
	return resultOrNilOnFetchError(ctx, provider, http.MethodGet, endpoint, bearer(tokens.AccessToken), nil, func(profile map[string]any) (*UserInfoResult, error) {
		return mapper(ctx, provider, profile)
	})
}
