package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/lastloginmethod"
	"github.com/pers0na2dev/single-auth/plugins/multisession"
	"github.com/pers0na2dev/single-auth/plugins/oidcprovider"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/passkey"
	"github.com/pers0na2dev/single-auth/plugins/sso"
	"github.com/pers0na2dev/single-auth/plugins/username"
)

// TypeScript's exactOptionalPropertyTypes has no direct Go compiler flag.
// Pointer-valued options are the Go representation of the same omitted versus
// explicitly-false/zero distinction, so this consumer proves those states are
// nameable and retained through the public root snapshot.
func main() {
	explicitFalse := false
	auth, err := singleauth.New(singleauth.Options{
		Secret: "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled:    true,
			AutoSignIn: &explicitFalse,
		},
		Account: singleauth.AccountOptions{
			AccountLinking: singleauth.AccountLinkingOptions{Enabled: &explicitFalse},
		},
		Advanced: singleauth.AdvancedOptions{
			DisableCSRFCheck:   &explicitFalse,
			DisableOriginCheck: &explicitFalse,
		},
	})
	if err != nil {
		panic(err)
	}
	snapshot := auth.Options()
	if snapshot.EmailAndPassword.AutoSignIn == nil || *snapshot.EmailAndPassword.AutoSignIn ||
		snapshot.Account.AccountLinking.Enabled == nil || *snapshot.Account.AccountLinking.Enabled ||
		snapshot.Advanced.DisableCSRFCheck == nil || *snapshot.Advanced.DisableCSRFCheck ||
		snapshot.Advanced.DisableOriginCheck == nil || *snapshot.Advanced.DisableOriginCheck {
		panic("explicit false options collapsed into omitted values")
	}

	passkeyOptions := passkey.Options{
		RPID: "localhost", RPName: "App", Origin: "http://localhost:3000",
		Registration: passkey.RegistrationOptions{RequireSession: passkey.Bool(false)},
	}
	lastLoginOptions := lastloginmethod.Options{MaxAge: lastloginmethod.Int(0)}
	multiSessionOptions := multisession.Options{MaximumSessions: multisession.Int(0)}
	if passkeyOptions.Registration.RequireSession == nil || *passkeyOptions.Registration.RequireSession ||
		lastLoginOptions.MaxAge == nil || *lastLoginOptions.MaxAge != 0 ||
		multiSessionOptions.MaximumSessions == nil || *multiSessionOptions.MaximumSessions != 0 {
		panic("plugin optional states are not externally representable")
	}

	factories := []singleauth.PluginFactory{
		organization.NewFactory(organization.Options{CreatorRole: "owner"}),
		passkey.NewFactory(passkeyOptions),
		sso.NewFactory(sso.Options{}),
		oidcprovider.NewFactory(oidcprovider.Options{LoginPage: "/login"}),
		username.NewFactory(username.Options{}),
	}
	for _, factory := range factories {
		if factory.PluginID() == "" {
			panic("optional-property plugin factory has no public ID")
		}
	}
	fmt.Print("ok:tsconfig-exact-optional-property-types")
}
