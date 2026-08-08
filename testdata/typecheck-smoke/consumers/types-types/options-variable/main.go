package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/plugins/admin"
)

type user struct{ ID string }

func main() {
	options := admin.Options{}
	factory := admin.NewTypedFactory(options, func(any) (user, error) { return user{}, nil })
	var _ *admin.TypedFactory[user] = factory
	var _ admin.ErrorCodes = factory.ErrorCodes().Plugin
	fmt.Println("ok:types-types-options-variable")
}
