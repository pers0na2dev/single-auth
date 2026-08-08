package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/model"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/twofactor"
)

func probe(value singleauth.TypedSessionInference[twofactor.UserAdditionalFields, organization.SessionAdditionalFields]) {
	var _ model.Value[bool] = value.User.Additional.TwoFactorEnabled
	var _ model.Value[string] = value.Session.Additional.ActiveOrganizationID
	var _ string = value.User.Email
	var _ string = value.Session.Token
}

func main() {
	probe(singleauth.TypedSessionInference[twofactor.UserAdditionalFields, organization.SessionAdditionalFields]{})
	fmt.Println("ok:types-types-additional-fields")
}
