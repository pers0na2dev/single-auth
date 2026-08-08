package lastloginmethod

import (
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func invokeProbe(
	t *testing.T,
	options Options,
	path *string,
	params map[string]string,
	setCookies []string,
) contract.Response {
	t.Helper()
	plugin, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := engine.Endpoint{
		Name: "testProbe", Methods: []string{"POST"},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			for _, value := range setCookies {
				ctx.AddSetCookie(value)
			}
			return contract.NewResponse(contract.StatusOK, contract.Headers{}, nil), nil
		},
	}
	if path == nil {
		endpoint.ServerOnly = true
	} else {
		endpoint.Path = *path
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{endpoint}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := contract.NewRequest("POST", "/:direct", contract.RequestOptions{
		Scheme: "http", Host: "auth.test",
	})
	response, err := dispatcher.Invoke("testProbe", engine.DirectInput{
		Request: request, Params: params,
	})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func responseCookie(response contract.Response, name string) (cookies.SetCookie, bool) {
	for _, value := range response.Headers().Values("Set-Cookie") {
		for _, cookie := range cookies.ParseSetCookieHeader(value) {
			if cookie.Name == name {
				return cookie, true
			}
		}
	}
	return cookies.SetCookie{}, false
}
