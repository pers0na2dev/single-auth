package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type fields struct{ Name *string }

func main() {
	result := singleauth.RequiredKeysOf(singleauth.OptionalKeyShape[fields]{})
	var _ singleauth.RequiredKeysAbsent = result
	if result.Bool() {
		panic("optional-only shape must not have required keys")
	}
	fmt.Println("ok:types-types-required-optional")
}
