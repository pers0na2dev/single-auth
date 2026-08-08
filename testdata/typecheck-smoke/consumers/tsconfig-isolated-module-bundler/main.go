package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/anonymous"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	"github.com/pers0na2dev/single-auth/plugins/lastloginmethod"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/storage"
)

type noSetCookieFactory struct{ built bool }

func (*noSetCookieFactory) PluginID() string { return "no-set-cookie" }

func (*noSetCookieFactory) Schema() (storage.Schema, error) {
	return storage.Schema{}, nil
}

func (factory *noSetCookieFactory) Build(singleauth.PluginHost) (engine.Plugin, error) {
	factory.built = true
	return engine.Plugin{ID: "no-set-cookie"}, nil
}

var _ singleauth.PluginFactory = (*noSetCookieFactory)(nil)

// isolatedModules verifies each source file without relying on cross-file
// type inference. The Go counterpart is a standalone external package that
// implements the public PluginFactory contract itself and composes it with
// independently imported built-in plugin packages.
func main() {
	custom := &noSetCookieFactory{}
	auth, err := singleauth.New(singleauth.Options{
		Secret:   "0123456789abcdef0123456789abcdef",
		BasePath: "/auth",
		PluginFactories: []singleauth.PluginFactory{
			bearer.NewFactory(bearer.Options{}),
			organization.NewFactory(organization.Options{}),
			lastloginmethod.NewFactory(lastloginmethod.Options{}),
			custom,
			anonymous.NewFactory(anonymous.Options{}),
		},
	})
	if err != nil {
		panic(err)
	}
	if auth.Registry() == nil || !custom.built {
		panic("external plugin factory was not registered")
	}
	fmt.Print("ok:tsconfig-isolated-module-bundler")
}
