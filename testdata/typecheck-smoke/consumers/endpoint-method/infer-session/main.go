package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/customsession"
)

type projection struct {
	Extra struct {
		Field string `json:"field"`
	} `json:"extra"`
}

func requireInferred(result *customsession.TypedSessionResult[projection]) string {
	return result.Data.Extra.Field
}

func main() {
	_ = customsession.NewTypedFactory(customsession.TypedOptions[projection]{
		Enrich: func(customsession.SessionData, *engine.Context) (projection, error) {
			return projection{}, nil
		},
	})
	_ = requireInferred
	fmt.Println("ok:endpoint-method-infer-session")
}
