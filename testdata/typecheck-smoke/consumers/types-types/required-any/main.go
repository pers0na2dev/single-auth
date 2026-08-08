package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
	result := singleauth.RequiredKeysOf(singleauth.AnyKeyShape{})
	var _ singleauth.RequiredKeysAbsent = result
	if result.Bool() {
		panic("any must not have statically required keys")
	}
	fmt.Println("ok:types-types-required-any")
}
