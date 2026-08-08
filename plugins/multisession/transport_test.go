package multisession_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/core/engine"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestDirectNetHTTPFastHTTPAndFiberListSessions(t *testing.T) {
	auth := newAuth(t, nil, nil)
	_, cookie, token := signUp(t, auth, "", "transport@example.test")

	t.Run("direct", func(t *testing.T) {
		response, err := auth.Invoke("listDeviceSessions", engine.DirectInput{
			Request: directRequest(http.MethodGet, "/multi-session/list-device-sessions", cookie, nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		assertTransportList(t, response.Status(), response.Body(), token)

		activated, err := auth.Invoke("setActiveSession", engine.DirectInput{
			Request: directRequest(http.MethodPost, "/multi-session/set-active", cookie, map[string]any{
				"sessionToken": token,
			}),
		})
		if err != nil || activated.Status() != http.StatusOK || len(activated.Headers().Values("Set-Cookie")) == 0 {
			t.Fatalf("direct activate status=%d cookies=%#v err=%v body=%s",
				activated.Status(), activated.Headers().Values("Set-Cookie"), err, activated.Body())
		}
	})

	t.Run("net/http", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodGet,
			testBaseURL+"/api/auth/multi-session/list-device-sessions",
			nil,
		)
		request.Header.Set("Cookie", cookie)
		recorder := httptest.NewRecorder()
		auth.Handler().ServeHTTP(recorder, request)
		assertTransportList(t, recorder.Code, recorder.Body.Bytes(), token)
	})

	t.Run("fasthttp", func(t *testing.T) {
		handler := fasthttptransport.NewHandler(auth.Dispatcher())
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.Header.Set("Cookie", cookie)
		request.SetRequestURI(testBaseURL + "/api/auth/multi-session/list-device-sessions")
		var ctx fasthttpserver.RequestCtx
		ctx.Init(&request, nil, nil)
		handler(&ctx)
		assertTransportList(t, ctx.Response.StatusCode(), ctx.Response.Body(), token)
	})

	t.Run("fiber", func(t *testing.T) {
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(auth.Dispatcher()))
		request, err := http.NewRequest(
			http.MethodGet,
			testBaseURL+"/api/auth/multi-session/list-device-sessions",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Cookie", cookie)
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertTransportList(t, response.StatusCode, body, token)
	})
}

func assertTransportList(t *testing.T, status int, body []byte, token string) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var result []any
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || !hasSessionToken(t, result, token) {
		t.Fatalf("sessions = %#v, want token %q", result, token)
	}
}
