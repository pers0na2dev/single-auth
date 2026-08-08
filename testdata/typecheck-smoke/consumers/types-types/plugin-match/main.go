package main

import (
	"fmt"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/twofactor"
)

type testTypePlugin struct {
	PingEndpoint engine.TypedEndpoint[engine.GET]
}

func probe(context singleauth.TypedPluginContext2[*twofactor.TypedFactory, testTypePlugin]) {
	var _ *twofactor.TypedFactory = context.First()
	var _ engine.TypedEndpoint[engine.GET] = context.Second().PingEndpoint
	var _ singleauth.KnownPluginPresence = context.HasFirst()
	var _ bool = context.HasPlugin("non-exist-plugin")
}

func main() {
	probe(singleauth.TypedPluginContext2[*twofactor.TypedFactory, testTypePlugin]{})
	fmt.Println("ok:types-types-plugin-match")
}
