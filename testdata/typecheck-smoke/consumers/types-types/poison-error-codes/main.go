package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type organizationCodes struct{ MemberNotFound singleauth.ErrorCode }

func main() {
	codes := singleauth.NewTypedErrorCodes(organizationCodes{})
	untypedPlugin := any(struct{}{})
	preserved := singleauth.PreserveErrorCodesWithUntypedPlugins(codes, untypedPlugin)
	var _ singleauth.TypedErrorCodes[organizationCodes] = preserved
	var _ singleauth.ErrorCode = preserved.Base.SessionExpired
	fmt.Println("ok:types-types-poison-error-codes")
}
