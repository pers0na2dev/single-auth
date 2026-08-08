package main

import (
	"context"
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/admin"
)

type user struct{ ID string }

func decode(any) (user, error) { return user{}, nil }

func createAuth(auth *singleauth.Auth) (*admin.TypedAuth[user], error) {
	return admin.NewTypedFactory(admin.Options{}, decode).BindAuth(auth)
}

func probe(auth *admin.TypedAuth[user]) {
	var _ func(context.Context, admin.CreateUserInput) (user, error) = auth.API().CreateUser
	var _ func(context.Context, admin.ListUsersInput) (admin.ListUsersResult[user], error) = auth.API().ListUsers
}

func main() {
	var _ func(*singleauth.Auth) (*admin.TypedAuth[user], error) = createAuth
	probe(nil)
	fmt.Println("ok:types-types-factory-return")
}
