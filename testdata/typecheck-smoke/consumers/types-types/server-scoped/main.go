package main

import (
	"fmt"
	"reflect"

	"github.com/pers0na2dev/single-auth/core/engine"
)

func main() {
	virtual := engine.NewTypedVirtualEndpoint("testVirtual", engine.GET{}, nil)
	server := engine.NewTypedServerScopedEndpoint("testServerScoped", "/test-server-scoped", engine.GET{}, nil)
	httpOnly := engine.NewTypedHTTPScopedEndpoint("testHTTPScoped", "/test-http-scoped", engine.GET{}, nil)
	nonAction := engine.NewTypedNonActionEndpoint("testNonAction", "/test-non-action", engine.GET{}, nil)
	api := engine.NewServerAPI2(virtual, server)
	var _ engine.TypedVirtualEndpoint[engine.GET] = api.First()
	var _ engine.TypedServerScopedEndpoint[engine.GET] = api.Second()
	if reflect.TypeOf(api).NumMethod() != 2 || httpOnly.Endpoint().Metadata[engine.EndpointScopeMetadataKey] != engine.EndpointScopeHTTP || nonAction.Endpoint().Metadata[engine.EndpointActionMetadataKey] != false {
		panic("typed server API scope filtering mismatch")
	}
	fmt.Println("ok:types-types-server-scoped")
}
