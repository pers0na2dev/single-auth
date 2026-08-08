package captcha

import (
	"context"
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testDispatcher(t *testing.T, options Options) *engine.Dispatcher {
	t.Helper()
	descriptor, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{{
		Name: "captchaPassThrough", Path: "/**", Methods: []string{http.MethodGet, http.MethodPost},
		Handler: func(*engine.Context) (contract.Response, error) {
			return contract.NewResponse(http.StatusNoContent, contract.Headers{}, nil), nil
		},
	}}, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	basePath := options.Runtime.BasePath
	if basePath == "" {
		basePath = defaultBasePath
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: basePath})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func dispatchCaptcha(
	t *testing.T,
	dispatcher *engine.Dispatcher,
	ctx context.Context,
	method string,
	path string,
	headers contract.Headers,
) contract.Response {
	t.Helper()
	response, err := dispatcher.Dispatch(contract.NewRequest(method, path, contract.RequestOptions{
		Context: ctx, Scheme: "http", Host: "auth.test", Headers: headers,
	}))
	if err != nil {
		t.Fatalf("dispatch = %v", err)
	}
	return response
}

func captchaHeaders(token string) contract.Headers {
	headers := contract.Headers{}
	if token != "" {
		headers.Add("x-captcha-response", token)
	}
	return headers
}
