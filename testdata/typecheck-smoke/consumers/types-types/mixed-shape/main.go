package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/admin"
	"github.com/pers0na2dev/single-auth/plugins/organization"
)

type user struct{ ID string }

func probe(apis singleauth.PluginAPIs2[admin.TypedDirectAPI[user], organization.TypedDirectAPI]) {
	var _ func(context.Context, admin.CreateUserInput) (user, error) = apis.First.CreateUser
	var _ func(context.Context, organization.CreateOrganizationInput) (organization.CreateOrganizationResult, error) = apis.Second.CreateOrganization
}

func main() {
	probe(singleauth.ComposePluginAPIs2(admin.TypedDirectAPI[user]{}, organization.TypedDirectAPI{}))
	fmt.Println("ok:types-types-mixed-shape")
}
