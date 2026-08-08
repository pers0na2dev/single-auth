package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func requireGET(engine.TypedEndpoint[engine.GET]) {}

func main() {
	endpoint := engine.NewTypedEndpoint(
		"getProbe", "/test-get", engine.GET{},
		func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(200, map[string]bool{"ok": true})
		},
	)
	requireGET(endpoint)
	methods := endpoint.Methods()
	if len(methods) != 1 || methods[0] != "GET" || endpoint.Endpoint().Methods[0] != "GET" {
		panic("GET method marker was not preserved")
	}
	fmt.Println("ok:endpoint-method-endpoint-get")
}
