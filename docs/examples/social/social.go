// Package social contains a compile-checked built-in provider setup example.
package social

import (
	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/protocol/providers"
)

// Google constructs a root runtime with Google social sign-in enabled.
func Google(clientID, clientSecret, authSecret string) (*singleauth.Auth, error) {
	google, err := providers.Google(providers.Options{
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, err
	}
	return singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  authSecret,
		SocialProviders: map[string]*providers.Provider{
			google.ID: google,
		},
		TrustedOrigins: []string{"https://app.example.com"},
	})
}
