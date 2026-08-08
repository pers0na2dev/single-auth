package main

import (
	"fmt"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func requireDELETE(engine.TypedEndpoint[engine.DELETE]) {}

func main() {
	endpoint := engine.NewTypedPathlessEndpoint(
		"deleteProbe", engine.DELETE{},
		func(*engine.Context) (contract.Response, error) {
			return contract.JSONResponse(200, map[string]bool{"deleted": true})
		},
	)
	requireDELETE(endpoint)
	runtime := endpoint.Endpoint()
	if runtime.Path != "" || !runtime.ServerOnly || len(runtime.Methods) != 1 || runtime.Methods[0] != "DELETE" {
		panic("pathless DELETE declaration was not preserved")
	}
	fmt.Println("ok:endpoint-method-endpoint-pathless")
}
