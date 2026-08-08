package singleauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/emailotp"
	"github.com/pers0na2dev/single-auth/plugins/jwt"
	"github.com/pers0na2dev/single-auth/plugins/organization"
	"github.com/pers0na2dev/single-auth/plugins/twofactor"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

const serverOnlyEndpointSuite = "server-only endpoints::"

var serverOnlyEndpointNames = []string{
	"setPassword",
	"addMember",
	"viewBackupCodes",
	"generateTOTP",
	"createVerificationOTP",
	"getVerificationOTP",
	"signJWT",
	"verifyJWT",
}

func TestServerOnlyEndpointsHTTPBehavior(t *testing.T) {
	auth := newServerOnlyEndpointsAuth(t)

	for _, name := range serverOnlyEndpointNames {
		name := name
		t.Run(serverOnlyEndpointSuite+"registers "+name+" on auth.api with no HTTP route", func(t *testing.T) {
			endpoint, exists := auth.Registry().Endpoint(name)
			if !exists {
				t.Fatalf("%s is not registered in the trusted direct API", name)
			}
			if endpoint.Path != "" {
				t.Fatalf("%s direct endpoint path=%q, want no HTTP path", name, endpoint.Path)
			}
			if !endpoint.ServerOnly || endpoint.Metadata[engine.ServerOnlyMetadataKey] != true {
				t.Fatalf("%s server-only metadata=%#v endpoint=%#v", name, endpoint.Metadata, endpoint)
			}

			// upstream implementation exposes a named auth.api function. Go normalizes that
			// dynamic surface to API().Call(name, input); an invalid payload may be
			// rejected by the handler, but it must never look like an unknown name.
			result, err := auth.API().Call(t.Context(), name, singleauth.DirectCallInput{
				Scheme: "http", Host: "localhost:3000", Body: map[string]any{},
			})
			if apiErr, ok := contract.AsAPIError(err); ok && apiErr.Code == "ENDPOINT_NOT_FOUND" {
				t.Fatalf("%s direct call was not registered: status=%d err=%v", name, result.Response.Status(), err)
			}
		})
	}

	t.Run(serverOnlyEndpointSuite+"keeps an endpoint off the router when it is marked SERVER_ONLY despite a path", func(t *testing.T) {
		direct, err := auth.API().Call(t.Context(), "serverOnlyMarkedProbe", singleauth.DirectCallInput{
			Method: http.MethodPost, Scheme: "http", Host: "localhost:3000", Body: map[string]any{},
		})
		if err != nil {
			t.Fatal(err)
		}
		value, ok := direct.Value.(map[string]any)
		if !ok || value["reached"] != true {
			t.Fatalf("marked endpoint direct result=%#v", direct.Value)
		}

		forEachServerOnlyTransport(t, auth, func(t *testing.T, exchange serverOnlyExchange) {
			marked := exchangeJSON(t, exchange, "/api/auth/server-only-probe/marked", map[string]any{})
			if marked != http.StatusNotFound {
				t.Fatalf("marked HTTP status=%d, want 404", marked)
			}
			routable := exchangeJSON(t, exchange, "/api/auth/server-only-probe/routable", map[string]any{})
			if routable == http.StatusNotFound {
				t.Fatalf("unmarked control HTTP status=%d, want non-404", routable)
			}
		})
	})

	t.Run(serverOnlyEndpointSuite+"does not route POST /organization/add-member", func(t *testing.T) {
		forEachServerOnlyTransport(t, auth, func(t *testing.T, exchange serverOnlyExchange) {
			addMember := exchangeJSON(t, exchange, "/api/auth/organization/add-member", map[string]any{
				"userId": "attacker-user-id", "role": "owner", "organizationId": "victim-org-id",
			})
			if addMember != http.StatusNotFound {
				t.Fatalf("add-member HTTP status=%d, want 404", addMember)
			}
			removeMember := exchangeJSON(t, exchange, "/api/auth/organization/remove-member", map[string]any{
				"memberIdOrEmail": "victim-member-id",
			})
			if removeMember != http.StatusUnauthorized {
				t.Fatalf("remove-member control HTTP status=%d, want 401", removeMember)
			}
		})
	})

	t.Run(serverOnlyEndpointSuite+"does not route POST /two-factor/view-backup-codes", func(t *testing.T) {
		forEachServerOnlyTransport(t, auth, func(t *testing.T, exchange serverOnlyExchange) {
			status := exchangeJSON(t, exchange, "/api/auth/two-factor/view-backup-codes", map[string]any{
				"userId": "victim-user-id",
			})
			if status != http.StatusNotFound {
				t.Fatalf("view-backup-codes HTTP status=%d, want 404", status)
			}
		})
	})
}

func newServerOnlyEndpointsAuth(t *testing.T) *singleauth.Auth {
	t.Helper()
	organizationPlugin := organization.MustNew(organization.Options{})
	auth, err := singleauth.New(singleauth.Options{
		BaseURL: "http://localhost:3000",
		Secret:  "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{
			Enabled: true,
			Password: singleauth.PasswordOptions{
				Hash:   func(password string) (string, error) { return "hash:" + password, nil },
				Verify: func(hash, password string) bool { return hash == "hash:"+password },
			},
		},
		PluginFactories: []singleauth.PluginFactory{
			organizationPlugin,
			twofactor.NewFactory(twofactor.Options{}),
			emailotp.NewFactory(emailotp.Options{
				SendVerificationOTP: func(context.Context, emailotp.OTPMessage, *engine.Context) error { return nil },
			}),
			jwt.NewFactory(jwt.Options{}),
		},
		Endpoints: []engine.Endpoint{
			{
				Name: "serverOnlyMarkedProbe", Path: "/server-only-probe/marked",
				Methods:  []string{http.MethodPost},
				Metadata: map[string]any{engine.ServerOnlyMetadataKey: true},
				Handler: func(*engine.Context) (contract.Response, error) {
					return contract.JSONResponse(contract.StatusOK, map[string]bool{"reached": true})
				},
			},
			{
				Name: "serverOnlyRoutableProbe", Path: "/server-only-probe/routable",
				Methods: []string{http.MethodPost},
				Handler: func(*engine.Context) (contract.Response, error) {
					return contract.JSONResponse(contract.StatusOK, map[string]bool{"reached": true})
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

type serverOnlyExchange func(method, target string, body []byte) (int, error)

func forEachServerOnlyTransport(
	t *testing.T,
	auth *singleauth.Auth,
	assert func(*testing.T, serverOnlyExchange),
) {
	t.Helper()
	for _, name := range []string{"net-http", "fasthttp", "fiber"} {
		name := name
		t.Run(name, func(t *testing.T) {
			assert(t, newServerOnlyExchange(t, name, auth))
		})
	}
}

func exchangeJSON(t *testing.T, exchange serverOnlyExchange, target string, body any) int {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	status, err := exchange(http.MethodPost, target, encoded)
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func newServerOnlyExchange(t *testing.T, name string, auth *singleauth.Auth) serverOnlyExchange {
	t.Helper()
	switch name {
	case "net-http":
		return func(method, target string, body []byte) (int, error) {
			request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			auth.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			_, err := io.Copy(io.Discard, response.Body)
			return response.StatusCode, err
		}
	case "fasthttp":
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		return func(method, target string, body []byte) (int, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(method)
			request.Header.SetHost("localhost:3000")
			request.Header.SetContentType("application/json")
			request.SetRequestURI(target)
			request.SetBody(body)
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
				nil,
			)
			handler(&requestContext)
			return requestContext.Response.StatusCode(), nil
		}
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		return func(method, target string, body []byte) (int, error) {
			request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
			if err != nil {
				return 0, err
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return 0, err
			}
			defer response.Body.Close()
			_, err = io.Copy(io.Discard, response.Body)
			return response.StatusCode, err
		}
	default:
		t.Fatalf("unknown server-only transport %q", name)
		return nil
	}
}
