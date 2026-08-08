package customsession

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func transportDispatcher(t *testing.T) *engine.Dispatcher {
	t.Helper()
	_, dispatcher := newTestPlugin(t, func(options *Options) {
		options.Runtime.GetSession = func(*engine.Context) (contract.Response, error) {
			return testSessionResponse("transport-user", "transport-token", contract.NewHeaders(
				contract.HeaderField{Name: "Set-Cookie", Value: "single-auth.session_token=transport-token; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"},
				contract.HeaderField{Name: "Set-Cookie", Value: "single-auth.session_data=transport-cache; Max-Age=300; Path=/; HttpOnly; SameSite=Lax"},
			)), nil
		}
	})
	return dispatcher
}

func TestNetHTTPFastHTTPAndFiberPreserveCustomSession(t *testing.T) {
	t.Run("net/http", func(t *testing.T) {
		handler := nethttptransport.NewHandler(transportDispatcher(t))
		request := httptest.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/get-session", nil)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		assertTransportResponse(t, recorder.Code, recorder.Header().Values("Set-Cookie"), recorder.Body.Bytes())
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(transportDispatcher(t))
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.SetRequestURI("http://auth.example.test/api/auth/get-session")
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		setCookies := make([]string, 0, 2)
		ctx.Response.Header.VisitAllCookie(func(_, value []byte) {
			setCookies = append(setCookies, string(value))
		})
		assertTransportResponse(t, ctx.Response.StatusCode(), setCookies, ctx.Response.Body())
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(transportDispatcher(t)))
		request, err := http.NewRequest(http.MethodGet, "http://auth.example.test/api/auth/get-session", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertTransportResponse(t, response.StatusCode, response.Header.Values("Set-Cookie"), body)
	})
}

func assertTransportResponse(t *testing.T, status int, setCookies []string, body []byte) {
	t.Helper()
	if status != http.StatusOK || len(setCookies) != 2 {
		t.Fatalf("status=%d cookies=%#v body=%s", status, setCookies, body)
	}
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if value["subject"] != "transport-user" || value["token"] != "transport-token" {
		t.Fatalf("response = %#v", value)
	}
}
