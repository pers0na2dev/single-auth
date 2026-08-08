package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

type getOrPost = engine.MethodSet2[engine.GET, engine.POST]

func requireGETOrPOST(engine.TypedEndpoint[getOrPost]) {}

func main() {
	endpoint := engine.NewTypedEndpoint(
		"multiProbe", "/test-multi", engine.Methods2(engine.GET{}, engine.POST{}),
		func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(200, map[string]bool{"ok": true})
		},
	)
	requireGETOrPOST(endpoint)
	methods := endpoint.Methods()
	if len(methods) != 2 || methods[0] != "GET" || methods[1] != "POST" {
		panic("method union was not preserved")
	}
	methods[0] = "DELETE"
	if endpoint.Methods()[0] != "GET" || endpoint.Endpoint().Methods[0] != "GET" {
		panic("mutable method slice aliases the typed declaration")
	}
	fmt.Println("ok:endpoint-method-endpoint-array")
}
