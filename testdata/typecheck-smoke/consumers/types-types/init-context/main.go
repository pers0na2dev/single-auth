package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type extension struct {
	TestValue  int
	TestHelper func() string
}

func probe(context singleauth.TypedContext[extension]) {
	var _ int = context.Extension().TestValue
	var _ func() string = context.Extension().TestHelper
}

func main() {
	probe(singleauth.TypedContext[extension]{})
	fmt.Println("ok:types-types-init-context")
}
