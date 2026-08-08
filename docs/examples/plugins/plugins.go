// Package plugins contains a compile-checked plugin-factory setup example.
package plugins

import (
	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/apikey"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	"github.com/pers0na2dev/single-auth/plugins/twofactor"
)

// New constructs an auth runtime whose schema and routes include four
// stateful server plugins.
func New(secret string) (*singleauth.Auth, error) {
	return singleauth.New(singleauth.Options{
		BaseURL: "https://auth.example.com",
		Secret:  secret,
		PluginFactories: []singleauth.PluginFactory{
			organization.NewFactory(organization.Options{}),
			apikey.NewFactory(apikey.Options{}),
			twofactor.NewFactory(twofactor.Options{}),
			passkey.NewFactory(passkey.Options{
				RPID:   "example.com",
				RPName: "Example",
				Origin: "https://app.example.com",
			}),
		},
		TrustedOrigins: []string{"https://app.example.com"},
	})
}
