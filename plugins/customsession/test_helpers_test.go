package customsession

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func testSessionResponse(userID, token string, headers contract.Headers) contract.Response {
	response, err := contract.JSONResponse(http.StatusOK, map[string]any{
		"user": map[string]any{
			"id": userID, "name": "Ada Lovelace", "email": "ada@example.com",
			"role": "admin",
		},
		"session": map[string]any{
			"id": "session-" + userID, "userId": userID, "token": token,
			"custom": "serialized-session-field",
		},
	})
	if err != nil {
		panic(err)
	}
	return response.WithHeaders(headers)
}

func newTestPlugin(
	t *testing.T,
	configure func(*Options),
) (engine.Plugin, *engine.Dispatcher) {
	t.Helper()
	options := Options{
		Enrich: func(data SessionData, _ *engine.Context) (any, error) {
			return map[string]any{
				"subject": data.User["id"],
				"role":    data.User["role"],
				"token":   data.Session["token"],
			}, nil
		},
		Runtime: Runtime{GetSession: func(*engine.Context) (contract.Response, error) {
			return testSessionResponse("user-1", "token-1", contract.NewHeaders()), nil
		}},
	}
	if configure != nil {
		configure(&options)
	}
	descriptor, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry([]engine.Endpoint{coreGetSessionEndpoint()}, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return descriptor, dispatcher
}

func coreGetSessionEndpoint() engine.Endpoint {
	return engine.Endpoint{
		Name: "getSession", Path: "/get-session", Methods: []string{http.MethodGet, http.MethodPost},
		Handler: func(*engine.Context) (contract.Response, error) {
			panic("custom-session override did not replace the core endpoint")
		},
	}
}

func dispatchGetSession(t *testing.T, dispatcher *engine.Dispatcher) (contract.Response, error) {
	t.Helper()
	request := contract.NewRequest(http.MethodGet, "/api/auth/get-session", contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "auth.example.test",
	})
	return dispatcher.Dispatch(request)
}

func decodeResponse(t *testing.T, response contract.Response) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(response.Body(), &value); err != nil {
		t.Fatalf("decode %q: %v", response.Body(), err)
	}
	return value
}

func responseMap(t *testing.T, response contract.Response) map[string]any {
	t.Helper()
	value, ok := decodeResponse(t, response).(map[string]any)
	if !ok {
		t.Fatalf("response = %s, want object", response.Body())
	}
	return value
}
