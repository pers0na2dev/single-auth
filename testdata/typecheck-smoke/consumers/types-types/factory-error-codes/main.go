package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/plugins/admin"
)

type user struct{}

func main() {
	factory := admin.NewTypedFactory(admin.Options{}, func(any) (user, error) { return user{}, nil })
	codes := factory.ErrorCodes()
	var _ singleauth.ErrorCode = codes.Base.SessionExpired
	var _ singleauth.ErrorCode = codes.Plugin.UserAlreadyExists
	fmt.Println("ok:types-types-factory-error-codes")
}
