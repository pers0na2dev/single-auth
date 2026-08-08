package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
)

type projection struct {
	Custom bool `json:"custom"`
}

func requireOverride(api customsession.TypedDirectAPI[projection]) {
	var getSession func(context.Context, singleauth.GetSessionInput) (*customsession.TypedSessionResult[projection], error) = api.GetSession
	var signOut func(context.Context, singleauth.SignOutInput) (singleauth.SignOutResult, error) = api.SignOut
	_, _ = getSession, signOut
}

func main() {
	factory := customsession.NewTypedFactory(customsession.TypedOptions[projection]{
		Enrich: func(customsession.SessionData, *engine.Context) (projection, error) {
			return projection{Custom: true}, nil
		},
	})
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "epM3thod_Ov3rride_9Zq7-L2x8_N4v6_C1k5_R0p3",
		PluginFactories: []singleauth.PluginFactory{factory},
	})
	typed, err := factory.BindAuth(auth)
	if err != nil {
		panic(err)
	}
	requireOverride(typed.API())
	fmt.Println("ok:endpoint-method-override-clean")
}
