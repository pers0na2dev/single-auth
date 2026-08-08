package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type fields struct{ Name string }

func main() {
	result := singleauth.RequiredKeysOf(singleauth.RequiredKeyShape[fields]{})
	var _ singleauth.RequiredKeysPresent = result
	if !result.Bool() {
		panic("required field marker lost")
	}
	fmt.Println("ok:types-types-required-present")
}
