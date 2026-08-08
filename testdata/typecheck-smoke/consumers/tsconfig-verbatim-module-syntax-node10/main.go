package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	singleauth "github.com/pers0na2dev/single-auth"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

// Go imports are always explicit package imports; there is no type-erased
// import rewriting comparable to verbatimModuleSyntax or Node10 resolution.
// This external consumer therefore names the canonical module and transport
// subpackage verbatim, assigns both public handlers to net/http, and executes
// one request through the imported adapter.
func main() {
	auth, err := singleauth.New(singleauth.Options{
		Secret: "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		panic(err)
	}
	var rootHandler http.Handler = auth
	var adapterHandler http.Handler = nethttptransport.NewHandler(auth.Dispatcher())
	if rootHandler == nil || adapterHandler == nil {
		panic("public net/http handler surface is incomplete")
	}

	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/auth/get-session", nil)
	response := httptest.NewRecorder()
	adapterHandler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		panic(fmt.Sprintf("get-session status=%d", response.Code))
	}
	fmt.Print("ok:tsconfig-verbatim-module-syntax-node10")
}
