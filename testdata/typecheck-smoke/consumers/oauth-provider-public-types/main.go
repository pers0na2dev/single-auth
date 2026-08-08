package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/plugins/oauthprovider"
)

func main() {
	var options oauthprovider.OAuthOptions
	if options.GrantTypes != nil {
		panic("zero-value OAuthOptions must preserve omitted grantTypes")
	}
	options.GrantTypes = []oauthprovider.GrantType{
		oauthprovider.GrantTypeAuthorizationCode,
		oauthprovider.GrantTypeClientCredentials,
		oauthprovider.GrantTypeRefreshToken,
	}

	var confidential oauthprovider.AuthMethod = oauthprovider.AuthMethodClientSecretBasic
	var tokenMethod oauthprovider.TokenEndpointAuthMethod = confidential
	tokenMethod = oauthprovider.TokenEndpointAuthMethodNone
	if len(options.GrantTypes) != 3 || tokenMethod != "none" {
		panic("public OAuth provider helper types are incomplete")
	}
	fmt.Print("ok:oauth-provider-public-types")
}
