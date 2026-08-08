package main

import (
	"fmt"
	"time"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/model"
)

func probe(value singleauth.TypedSessionInference[singleauth.NoAdditionalFields, singleauth.NoAdditionalFields]) {
	var _ string = value.Session.ID
	var _ time.Time = value.Session.CreatedAt
	var _ time.Time = value.Session.UpdatedAt
	var _ string = value.Session.UserID
	var _ time.Time = value.Session.ExpiresAt
	var _ string = value.Session.Token
	var _ model.Value[string] = value.Session.IPAddress
	var _ model.Value[string] = value.Session.UserAgent
	var _ string = value.User.ID
	var _ time.Time = value.User.CreatedAt
	var _ time.Time = value.User.UpdatedAt
	var _ string = value.User.Email
	var _ bool = value.User.EmailVerified
	var _ string = value.User.Name
	var _ model.Value[string] = value.User.Image
}

func main() {
	probe(singleauth.TypedSessionInference[singleauth.NoAdditionalFields, singleauth.NoAdditionalFields]{})
	fmt.Println("ok:types-types-base-session")
}
