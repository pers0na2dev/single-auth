package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
)

type projection struct {
	CustomField string `json:"customField"`
}

func concreteResult(api customsession.TypedDirectAPI[projection]) string {
	result, _ := api.GetSession(context.Background(), singleauth.GetSessionInput{})
	if result == nil {
		return ""
	}
	return result.Data.CustomField
}

func main() {
	_ = customsession.NewTypedFactory(customsession.TypedOptions[projection]{
		Enrich: func(customsession.SessionData, *engine.Context) (projection, error) {
			return projection{CustomField: "value"}, nil
		},
	})
	_ = concreteResult
	fmt.Println("ok:endpoint-method-server-not-any")
}
