package oauthprovider

// GrantType is a grant type accepted by the OAuth token endpoint.
type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)

// AuthMethod is a confidential-client authentication method.
type AuthMethod string

const (
	AuthMethodClientSecretBasic AuthMethod = "client_secret_basic"
	AuthMethodClientSecretPost  AuthMethod = "client_secret_post"
)

// TokenEndpointAuthMethod includes confidential-client authentication and
// the public-client "none" method. The alias preserves assignment from an
// AuthMethod just as single-auth's TypeScript union does.
type TokenEndpointAuthMethod = AuthMethod

const TokenEndpointAuthMethodNone TokenEndpointAuthMethod = "none"

// OAuthOptions exposes package-wide OAuth provider options. A nil GrantTypes
// slice represents the omitted TypeScript option and keeps single-auth's
// default grant set; a non-nil slice is an explicit configured set.
type OAuthOptions struct {
	GrantTypes []GrantType
}
