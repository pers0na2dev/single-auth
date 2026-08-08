package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func requireBaseMethods(api singleauth.DirectAPI) {
	var getSession func(context.Context, singleauth.GetSessionInput) (*singleauth.SessionResult, error) = api.GetSession
	var signOut func(context.Context, singleauth.SignOutInput) (singleauth.SignOutResult, error) = api.SignOut
	var signUp = api.SignUpEmail
	var signIn = api.SignInEmail
	_, _, _, _ = getSession, signOut, signUp, signIn
}

func main() {
	custom := engine.Plugin{ID: "test-plugin", Endpoints: []engine.Endpoint{{
		Name: "customEndpoint", Path: "/custom", Methods: []string{"POST"},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(200, map[string]bool{"result": true})
		},
	}}}
	auth := singleauth.MustNew(singleauth.Options{
		BaseURL: "http://localhost:3000", Secret: "endpoint-method-plugin-base-secret",
		Plugins: []engine.Plugin{custom},
	})
	requireBaseMethods(auth.API())
	if _, exists := auth.Registry().Endpoint("customEndpoint"); !exists {
		panic("custom endpoint was not registered")
	}
	fmt.Println("ok:endpoint-method-plugin-base-api")
}
