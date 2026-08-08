package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func requirePOST(engine.TypedEndpoint[engine.POST]) {}

func main() {
	endpoint := engine.NewTypedEndpoint(
		"postProbe", "/test", engine.POST{},
		func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(200, map[string]bool{"ok": true})
		},
	)
	requirePOST(endpoint)
	methods := endpoint.Methods()
	if len(methods) != 1 || methods[0] != "POST" || endpoint.Endpoint().Methods[0] != "POST" {
		panic("POST method marker was not preserved")
	}
	fmt.Println("ok:endpoint-method-endpoint-post")
}
