package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
)

type projection struct {
	User struct {
		FirstName string `json:"firstName"`
	} `json:"user"`
	Custom struct {
		Data string `json:"data"`
	} `json:"custom"`
}

func compileServerAPI(auth *customsession.TypedAuth[projection]) {
	api := auth.API()
	var getSession func(context.Context, singleauth.GetSessionInput) (*customsession.TypedSessionResult[projection], error) = api.GetSession
	_ = getSession
}

func main() {
	factory := customsession.NewTypedFactory(customsession.TypedOptions[projection]{
		Enrich: func(customsession.SessionData, *engine.Context) (projection, error) {
			return projection{}, nil
		},
	})
	var _ singleauth.PluginFactory = factory
	fmt.Println("ok:endpoint-method-server-custom-session-api")
}
