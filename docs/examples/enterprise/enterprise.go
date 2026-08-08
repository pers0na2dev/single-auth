// Package enterprise contains compile-checked examples for stateful server
// plugins with ordering and protocol dependencies.
package enterprise

import (
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/apikey"
	jwtplugin "github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/plugins/oauthprovider"
	"github.com/pers0na2dev/single-auth/plugins/sso"
)

// APIKeys configures a user-owned key class with hashed credentials, quotas,
// permissions, expiry, and optional session projection.
func APIKeys(secret string) (*singleauth.Auth, error) {
	keys := apikey.NewFactory(apikey.Options{
		Configurations: []apikey.Configuration{{
			ConfigID:                "service",
			References:              apikey.ReferenceUser,
			DefaultPrefix:           "sa",
			DefaultKeyLength:        32,
			EnableMetadata:          true,
			RateLimitEnabled:        apikey.Bool(true),
			RateLimitTimeWindow:     time.Minute,
			RateLimitMax:            120,
			DefaultExpiresIn:        90 * 24 * time.Hour,
			DefaultPermissions:      map[string][]string{"documents": {"read"}},
			EnableSessionForAPIKeys: true,
			APIKeyHeaders:           []string{"x-api-key"},
		}},
		DeleteExpiredOnWrite: true,
	})
	return singleauth.New(singleauth.Options{
		BaseURL:         "https://auth.example.com",
		Secret:          secret,
		PluginFactories: []singleauth.PluginFactory{keys},
	})
}

// SSO configures one static OpenID Connect enterprise provider.
func SSO(clientID, clientSecret, authSecret string) (*singleauth.Auth, error) {
	return singleauth.New(singleauth.Options{
		BaseURL:        "https://auth.example.com",
		Secret:         authSecret,
		TrustedOrigins: []string{"https://app.example.com"},
		PluginFactories: []singleauth.PluginFactory{
			sso.NewFactory(sso.Options{
				DefaultSSO: []sso.DefaultProvider{{
					ProviderID: "company-oidc",
					Domain:     "example.com",
					OIDCConfig: &sso.OIDCConfig{
						Issuer:            "https://id.example.com",
						DiscoveryEndpoint: "https://id.example.com/.well-known/openid-configuration",
						ClientID:          clientID,
						ClientSecret:      clientSecret,
						Scopes:            []string{"openid", "profile", "email"},
					},
				}},
				DisableImplicitSignUp: true,
				TrustEmailVerified:    true,
			}),
		},
	})
}

// OAuthAuthorizationServer configures the JWT dependency before the complete
// OAuth 2.1/OpenID Provider factory.
func OAuthAuthorizationServer(secret string) (*singleauth.Auth, error) {
	return singleauth.New(singleauth.Options{
		BaseURL: "https://identity.example.com",
		Secret:  secret,
		PluginFactories: []singleauth.PluginFactory{
			jwtplugin.NewFactory(jwtplugin.Options{}),
			oauthprovider.NewFactory(oauthprovider.Options{
				LoginPage:   "https://app.example.com/login",
				ConsentPage: "https://app.example.com/oauth/consent",
				Scopes:      []string{"openid", "profile", "email", "offline_access"},
			}),
		},
	})
}
