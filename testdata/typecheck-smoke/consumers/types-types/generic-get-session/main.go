package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

func probe[Output any](auth *singleauth.TypedAuth[Output]) {
	var _ func(context.Context, singleauth.GetSessionInput) (*singleauth.TypedSessionResult[Output], error) = auth.API().GetSession
}

func main() {
	probe[struct{}](nil)
	fmt.Println("ok:types-types-generic-get-session")
}
