package main

import (
	"fmt"
	"reflect"

	singleauth "github.com/pers0na2dev/single-auth"
)

func main() {
	withoutPlugins := singleauth.TypedSessionInference[singleauth.NoAdditionalFields, singleauth.NoAdditionalFields]{}
	withEmptyPlugins := withoutPlugins
	var same singleauth.TypedSessionInference[singleauth.NoAdditionalFields, singleauth.NoAdditionalFields] = withEmptyPlugins
	if reflect.TypeOf(same) != reflect.TypeOf(withoutPlugins) {
		panic("empty and omitted plugin inference differ")
	}
	fmt.Println("ok:types-types-empty-plugins")
}
