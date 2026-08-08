// Package oauth2 implements the OAuth 2.0/OIDC primitives shared by Better
// Auth providers.
package oauth2

import "time"

// Tokens is the reference implementation's normalized OAuth2 token response.
type Tokens struct {
	TokenType             string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scopes                []string
	IDToken               string
	Raw                   map[string]any
}

// UserInfo is the normalized social-provider identity.
type UserInfo struct {
	ID            string
	Name          string
	Email         *string
	Image         string
	EmailVerified bool
	Extra         map[string]any
}

// ProviderOptions is the runtime-neutral subset shared by provider factories.
type ProviderOptions struct {
	ClientID              any
	ClientSecret          string
	ClientKey             string
	Scopes                []string
	DisableDefaultScope   bool
	RedirectURI           string
	AuthorizationEndpoint string
	DisableIDTokenSignIn  bool
	DisableImplicitSignUp bool
	DisableSignUp         bool
	Prompt                string
	ResponseMode          string
	OverrideUserInfo      bool
}

// PrimaryClientID mirrors the reference implementation's string-or-array clientId behavior.
func PrimaryClientID(value any) (string, bool) {
	switch typed := value.(type) {
	case string:
		return typed, typed != ""
	case []string:
		if len(typed) == 0 || typed[0] == "" {
			return "", false
		}
		return typed[0], true
	case []any:
		if len(typed) == 0 {
			return "", false
		}
		primary, ok := typed[0].(string)
		return primary, ok && primary != ""
	default:
		return "", false
	}
}

func jsString(value any) string {
	if primary, ok := PrimaryClientID(value); ok {
		return primary
	}
	// URLSearchParams.set receives undefined in a few permissive upstream code
	// paths, which Web IDL stringifies as "undefined".
	if value == nil {
		return "undefined"
	}
	return "undefined"
}
