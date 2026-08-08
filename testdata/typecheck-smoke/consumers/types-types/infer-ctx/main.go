package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
)

type query struct{ Page int }

func probe(context singleauth.TypedRequestContext[any, query]) {
	var _ int = context.Query.Page
	var _ any = context.Body
}

func main() {
	probe(singleauth.TypedRequestContext[any, query]{})
	fmt.Println("ok:types-types-infer-ctx")
}
