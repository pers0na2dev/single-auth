package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/organization"
)

func main() {
	inference := singleauth.TypedSessionInference[singleauth.NoAdditionalFields, organization.SessionAdditionalFields]{}
	untypedPlugin := any(struct{}{})
	preserved := singleauth.PreserveInferenceWithUntypedPlugins(inference, untypedPlugin)
	var _ singleauth.TypedSessionInference[singleauth.NoAdditionalFields, organization.SessionAdditionalFields] = preserved
	var _ string = preserved.Session.Token
	fmt.Println("ok:types-types-poison-infer")
}
