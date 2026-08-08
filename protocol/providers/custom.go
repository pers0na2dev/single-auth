package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pers0na2dev/single-auth/protocol/oauth2"
)

// CustomProvider describes a fully configured provider implementation. It is
// primarily intended for protocol plugins that must register providers at
// PluginFactory build time while retaining the root account/token lifecycle.
// All callbacks are snapshotted by NewCustomProvider.
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

// NewCustomProvider creates a provider backed by caller-supplied OAuth
// primitives. Required callbacks are validated up front so malformed plugin
// registrations cannot become request-time nil function panics.
func NewCustomProvider(input CustomProvider) (*Provider, error) {
	if input.ID == "" {
		return nil, fmt.Errorf("providers: custom provider ID is required")
	}
	if input.Name == "" {
		input.Name = input.ID
	}
	if input.CreateAuthorizationURL == nil {
		return nil, fmt.Errorf("providers: custom provider %q authorization callback is required", input.ID)
	}
	if input.ValidateAuthorizationCode == nil {
		return nil, fmt.Errorf("providers: custom provider %q token callback is required", input.ID)
	}
	if input.GetUserInfo == nil {
		return nil, fmt.Errorf("providers: custom provider %q user-info callback is required", input.ID)
	}

	options := input.Options
	options.Scopes = cloneStrings(input.Options.Scopes)
	metadata := input.Metadata
	metadata.DefaultScopes = cloneStrings(input.Metadata.DefaultScopes)
	metadata.SupportsRefresh = input.RefreshAccessToken != nil
	provider := &Provider{
		ID: input.ID, Name: input.Name, Options: options, Metadata: metadata,
		createAuthorizationURL: input.CreateAuthorizationURL,
		validateCode:           input.ValidateAuthorizationCode,
		refreshToken:           input.RefreshAccessToken,
		getUserInfo:            input.GetUserInfo,
		verifyIDToken:          input.VerifyIDToken,
	}
	return provider, nil
}
