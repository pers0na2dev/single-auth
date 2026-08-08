package bearer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/security/cookies"
	"github.com/pers0na2dev/single-auth/core/engine"
)

type bearerTestValues struct {
	Secret                     string
	SessionCookieName          string
	UnsignedToken              string
	SignedToken                string
	EncodedSignedToken         string
	URLSafeSignature           string
	InjectedCookieWithExisting string
	ExposedHeaders             string
}

var bearerCases = bearerTestValues{
	Secret:                     "secret-at-least-32-characters-long",
	SessionCookieName:          "single-auth.session_token",
	UnsignedToken:              "session-token",
	SignedToken:                "session-token.HSUilDsF/4P9cO3bi3vy0MP8pvUiwteom6MRcX57XHo=",
	EncodedSignedToken:         "session-token.HSUilDsF%2F4P9cO3bi3vy0MP8pvUiwteom6MRcX57XHo%3D",
	URLSafeSignature:           "HSUilDsF_4P9cO3bi3vy0MP8pvUiwteom6MRcX57XHo",
	InjectedCookieWithExisting: "theme=dark; single-auth.session_token=session-token.HSUilDsF%2F4P9cO3bi3vy0MP8pvUiwteom6MRcX57XHo%3D",
	ExposedHeaders:             "x-request-id, set-auth-token",
}

func loadBearerTestValues(t *testing.T) bearerTestValues {
	t.Helper()
	return bearerCases
}

type probeResult struct {
	Authorization string `json:"authorization"`
	Cookie        string `json:"cookie"`
	Session       string `json:"session"`
	SessionValid  bool   `json:"sessionValid"`
}

func probeEndpoint(secret, cookieName string) engine.Endpoint {
	return engine.Endpoint{
		Name: "probe", Path: "/probe", Methods: []string{"GET"},
		Handler: func(ctx *engine.Context) (contract.Response, error) {
			headers := ctx.Request().Headers()
			authorization := combinedHeaderValue(headers, "Authorization")
			cookieHeader := strings.Join(headers.Values("Cookie"), "; ")
			session, _ := cookies.Parse(cookieHeader).Get(cookieName)
			return contract.JSONResponse(contract.StatusOK, probeResult{
				Authorization: authorization,
				Cookie:        cookieHeader,
				Session:       session,
				SessionValid:  verifySignedCookie(session, secret),
			})
		},
	}
}

func newTestDispatcher(
	t *testing.T,
	options Options,
	endpoints ...engine.Endpoint,
) (*engine.Dispatcher, engine.Plugin) {
	t.Helper()
	plugin, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := engine.NewRegistry(endpoints, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher, plugin
}

func dispatch(
	t *testing.T,
	dispatcher *engine.Dispatcher,
	method, path string,
	headers contract.Headers,
) (contract.Response, error) {
	t.Helper()
	return dispatcher.Dispatch(contract.NewRequest(method, "/api/auth"+path, contract.RequestOptions{
		Context: context.Background(), Scheme: "http", Host: "localhost:3000", Headers: headers,
	}))
}

func decodeProbe(t *testing.T, response contract.Response) probeResult {
	t.Helper()
	var result probeResult
	if err := json.Unmarshal(response.Body(), &result); err != nil {
		t.Fatalf("decode probe %q: %v", response.Body(), err)
	}
	return result
}
