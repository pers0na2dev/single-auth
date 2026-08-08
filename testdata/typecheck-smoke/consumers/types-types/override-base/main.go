package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type overrideResult struct {
	OverriddenMarker bool `json:"overriddenMarker"`
}

func probe(api singleauth.TypedSignInEmailOverrideAPI[overrideResult]) {
	var _ func(context.Context, singleauth.NoBody) (overrideResult, error) = api.SignInEmail
	var _ func(context.Context, singleauth.SignOutInput) (singleauth.SignOutResult, error) = api.SignOut
}

func main() {
	probe(singleauth.TypedSignInEmailOverrideAPI[overrideResult]{})
	fmt.Println("ok:types-types-override-base")
}
