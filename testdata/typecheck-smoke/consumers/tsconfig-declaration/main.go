package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/admin"
	"github.com/pers0na2dev/single-auth/plugins/anonymous"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
	"github.com/pers0na2dev/single-auth/plugins/deviceauthorization"
	"github.com/pers0na2dev/single-auth/plugins/lastloginmethod"
	"github.com/pers0na2dev/single-auth/plugins/multisession"
	"github.com/pers0na2dev/single-auth/plugins/oauthproxy"
	"github.com/pers0na2dev/single-auth/plugins/oidcprovider"
	"github.com/pers0na2dev/single-auth/plugins/onetap"
	"github.com/pers0na2dev/single-auth/plugins/openapi"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	"github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/plugins/twofactor"
	"github.com/pers0na2dev/single-auth/plugins/username"
)

// The upstream declaration fixture catches package exports whose public type
// signatures accidentally mention private TypeScript names. Go has no
// declaration-emission phase, so this external module names and constructs the
// corresponding exported factories and callback signatures directly.
func main() {
	factories := []singleauth.PluginFactory{
		admin.NewFactory(admin.Options{}),
		anonymous.NewFactory(anonymous.Options{}),
		bearer.NewFactory(bearer.Options{}),
		customsession.NewFactory(customsession.Options{
			Enrich: func(data customsession.SessionData, _ *engine.Context) (any, error) {
				return data, nil
			},
		}),
		deviceauthorization.NewFactory(),
		lastloginmethod.NewFactory(lastloginmethod.Options{}),
		multisession.NewFactory(multisession.Options{}),
		oauthproxy.NewFactory(),
		oidcprovider.NewFactory(oidcprovider.Options{
			LoginPage:   "/auth/sign-in",
			ConsentPage: "/auth/oauth/consent",
			Scopes:      []string{"openid", "email"},
		}),
		onetap.NewFactory(onetap.Options{ClientID: "google-client"}),
		openapi.NewFactory(openapi.Options{}),
		organization.NewFactory(organization.Options{}),
		passkey.NewFactory(passkey.Options{
			RPID: "localhost", RPName: "App", Origin: "http://localhost:3000",
		}),
		sso.NewFactory(sso.Options{}),
		twofactor.NewFactory(twofactor.Options{}),
		username.NewFactory(username.Options{}),
	}
	for _, factory := range factories {
		if factory == nil || factory.PluginID() == "" {
			panic("public plugin factory is not constructible")
		}
	}

	auth, err := singleauth.New(singleauth.Options{
		Secret: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		panic(err)
	}
	if auth.Handler() == nil || auth.Dispatcher() == nil {
		panic("root public runtime surface is incomplete")
	}
	fmt.Print("ok:tsconfig-declaration")
}
