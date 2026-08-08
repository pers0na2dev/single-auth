package singleauth_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
)

func TestCallBehaviorDirectAPIHooksCookiesRedirectsAndErrors(t *testing.T) {
	auth := newCallBehaviorAuth(t)
	api := auth.API()

	call := func(query url.Values) (singleauth.DirectCallResult, error) {
		t.Helper()
		return api.Call(t.Context(), "callTest", singleauth.DirectCallInput{
			Method: http.MethodGet,
			Query:  query,
		})
	}
	assertValue := func(result singleauth.DirectCallResult, key, want string) {
		t.Helper()
		object, ok := result.Value.(map[string]any)
		if !ok || object[key] != want {
			t.Fatalf("direct value=%#v, want %s=%q", result.Value, key, want)
		}
	}

	result, err := call(nil)
	if err != nil {
		t.Fatal(err)
	}
	assertValue(result, "success", "true")
	if result.Response.Status() != http.StatusOK || !strings.Contains(
		strings.Join(result.Response.Headers().Values("Content-Type"), ","),
		"application/json",
	) {
		t.Fatalf("direct response=%d %#v", result.Response.Status(), result.Response.Headers().Fields())
	}

	serverOnly, err := api.Call(t.Context(), "callTestServerScoped", singleauth.DirectCallInput{Method: http.MethodGet})
	if err != nil || serverOnly.Value != "ok" {
		t.Fatalf("server-scoped result=%#v err=%v", serverOnly.Value, err)
	}

	before, err := call(url.Values{"testBeforeHook": {"true"}})
	if err != nil {
		t.Fatal(err)
	}
	assertValue(before, "before", "test")

	changed, err := call(url.Values{"testContext": {"context-changed"}})
	if err != nil {
		t.Fatal(err)
	}
	assertValue(changed, "success", "context-changed")

	after, err := call(url.Values{"testAfterHook": {"true"}})
	if err != nil {
		t.Fatal(err)
	}
	assertValue(after, "after", "test")

	globalBefore, err := call(url.Values{"testBeforeGlobal": {"true"}})
	if err != nil {
		t.Fatal(err)
	}
	assertValue(globalBefore, "before", "global")

	globalAfter, err := call(url.Values{"testAfterGlobal": {"true"}})
	if err != nil {
		t.Fatal(err)
	}
	assertValue(globalAfter, "after", "global")

	cookiesResult, err := api.Call(t.Context(), "callTestCookies", singleauth.DirectCallInput{
		Method: http.MethodPost,
		Body: map[string]any{"cookies": []map[string]string{{
			"name": "test-cookie", "value": "test-value",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cookiesResult.Response.Headers().Values("Set-Cookie"), ";"); !strings.Contains(got, "test-cookie=test-value") {
		t.Fatalf("direct Set-Cookie=%q", got)
	}

	cookiesAfter, err := api.Call(t.Context(), "callTestCookies", singleauth.DirectCallInput{
		Method: http.MethodPost,
		Query:  url.Values{"testAfterHook": {"true"}},
		Body: map[string]any{"cookies": []map[string]string{{
			"name": "test-cookie", "value": "test-value",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	setCookies := strings.Join(cookiesAfter.Response.Headers().Values("Set-Cookie"), ";")
	if !strings.Contains(setCookies, "test-cookie=test-value") || !strings.Contains(setCookies, "after=test") {
		t.Fatalf("after-hook Set-Cookie=%q", setCookies)
	}

	_, err = api.Call(t.Context(), "callTestThrow", singleauth.DirectCallInput{
		Method: http.MethodGet, Query: url.Values{"message": {"throw-api-error"}},
	})
	if typed, ok := contract.AsAPIError(err); !ok || typed.Status != http.StatusBadRequest || typed.Message != "Test error" {
		t.Fatalf("typed API error=%T %#v", err, err)
	}

	_, err = api.Call(t.Context(), "callTestThrow", singleauth.DirectCallInput{
		Method: http.MethodGet, Query: url.Values{"message": {"throw-error"}},
	})
	if err == nil || err.Error() != "Test error" {
		t.Fatalf("plain error=%T %v", err, err)
	}
	if _, typed := contract.AsAPIError(err); typed {
		t.Fatalf("plain error became APIError: %#v", err)
	}

	assertRedirect := func(message string, additional bool) {
		t.Helper()
		result, callErr := api.Call(t.Context(), "callTestThrow", singleauth.DirectCallInput{
			Method: http.MethodGet, Query: url.Values{"message": {message}},
		})
		typed, ok := contract.AsAPIError(callErr)
		if !ok || typed.Status != http.StatusFound || result.Response.Headers().Values("Location")[0] != "/test" {
			t.Fatalf("redirect result=%#v err=%T %#v", result.Response.Headers().Fields(), callErr, callErr)
		}
		if additional {
			if value, _ := result.Response.Headers().Get("key"); value != "value" {
				t.Fatalf("redirect additional header=%q", value)
			}
		}
	}
	assertRedirect("throw redirect", false)
	assertRedirect("redirect with additional header", true)

	for _, scenario := range []struct {
		message string
		want    string
	}{
		{message: "throw-after-hook", want: "from after hook"},
		{message: "throw-chained-hook", want: "from chained hook 2"},
	} {
		_, err := api.Call(t.Context(), "callTestThrow", singleauth.DirectCallInput{
			Method: http.MethodGet, Query: url.Values{"message": {scenario.message}},
		})
		typed, ok := contract.AsAPIError(err)
		if !ok || typed.Status != http.StatusBadRequest || !strings.Contains(typed.Message, scenario.want) {
			t.Fatalf("%s error=%T %#v", scenario.message, err, err)
		}
	}
}

func TestCallBehaviorGlobalBeforeContextMutationAndBearerSession(t *testing.T) {
	auth := newCallBehaviorAuth(t)
	created, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
		Name: "test", Email: "my-email@test.com", Password: "password",
	})
	if err != nil || created.Token == nil {
		t.Fatalf("sign-up result=%#v err=%v", created, err)
	}
	session, err := auth.API().GetSession(t.Context(), singleauth.GetSessionInput{
		Headers: contract.NewHeaders(contract.HeaderField{
			Name: "Authorization", Value: "Bearer " + *created.Token,
		}),
	})
	if err != nil || session == nil || session.User.Email != "changed@email.com" {
		t.Fatalf("bearer session=%#v err=%v", session, err)
	}
}

func TestCallBehaviorClientFetchAcrossTransports(t *testing.T) {
	auth := newCallBehaviorAuth(t)
	for _, profile := range callTransportProfiles(t, auth) {
		t.Run(profile.name, func(t *testing.T) {
			status, _, body, err := profile.exchange(http.MethodGet, "/api/auth/ok", nil)
			if err != nil {
				t.Fatal(err)
			}
			var okResult map[string]any
			if err := json.Unmarshal(body, &okResult); err != nil || status != http.StatusOK || okResult["ok"] != true {
				t.Fatalf("client /ok status=%d body=%s err=%v", status, body, err)
			}

			status, _, body, err = profile.exchange(http.MethodGet, "/api/auth/test?message=test", nil)
			if err != nil {
				t.Fatal(err)
			}
			var queryResult map[string]any
			if err := json.Unmarshal(body, &queryResult); err != nil || status != http.StatusOK || queryResult["success"] != "test" {
				t.Fatalf("client query status=%d body=%s err=%v", status, body, err)
			}

			cookieBody := []byte(`{"cookies":[{"name":"test-cookie","value":"test-value"}]}`)
			status, headers, body, err := profile.exchange(http.MethodPost, "/api/auth/test/cookies", cookieBody)
			if err != nil || status != http.StatusOK || !strings.Contains(strings.Join(headers.Values("Set-Cookie"), ";"), "test-cookie=test-value") {
				t.Fatalf("client cookies status=%d headers=%#v body=%s err=%v", status, headers, body, err)
			}
		})
	}
}

func newCallBehaviorAuth(t *testing.T) *singleauth.Auth {
	t.Helper()
	plugin := engine.Plugin{
		ID: "call-behavior",
		Endpoints: []engine.Endpoint{
			{
				Name: "callTest", Path: "/test", Methods: []string{http.MethodGet},
				Handler: func(ctx *engine.Context) (contract.Response, error) {
					message := callQuery(ctx).Get("message")
					if message == "" {
						message = "true"
					}
					return contract.JSONResponse(http.StatusOK, map[string]any{"success": message})
				},
			},
			{
				Name: "callTestServerScoped", ServerOnly: true,
				Handler: func(*engine.Context) (contract.Response, error) {
					return contract.JSONResponse(http.StatusOK, "ok")
				},
			},
			{
				Name: "callTestCookies", Path: "/test/cookies", Methods: []string{http.MethodPost},
				Handler: func(ctx *engine.Context) (contract.Response, error) {
					var input struct {
						Cookies []struct {
							Name  string `json:"name"`
							Value string `json:"value"`
						} `json:"cookies"`
					}
					if err := json.Unmarshal(ctx.Request().Body(), &input); err != nil {
						return contract.Response{}, err
					}
					for _, cookie := range input.Cookies {
						ctx.AddSetCookie(cookie.Name + "=" + cookie.Value)
					}
					return contract.JSONResponse(http.StatusOK, map[string]any{"success": true})
				},
			},
			{
				Name: "callTestThrow", Path: "/test/throw", Methods: []string{http.MethodGet},
				Handler: callThrowHandler,
			},
		},
		Hooks: engine.Hooks{
			Before: []engine.BeforeHook{{
				Matcher: func(ctx *engine.Context) (bool, error) { return ctx.Path() == "/test", nil },
				Handler: func(ctx *engine.Context) (*contract.Response, error) {
					query := callQuery(ctx)
					if query.Get("testBeforeHook") != "" {
						return callResponsePointer(map[string]any{"before": "test"}), nil
					}
					if value := query.Get("testContext"); value != "" {
						request := ctx.Request()
						ctx.ReplaceRequest(request.WithTarget(request.RawPath(), url.Values{"message": {value}}.Encode()))
					}
					return nil, nil
				},
			}},
			After: []engine.AfterHook{
				{
					Matcher: func(ctx *engine.Context) (bool, error) { return ctx.Path() == "/test", nil },
					Handler: func(ctx *engine.Context, _ contract.Response) (*contract.Response, error) {
						if callQuery(ctx).Get("testAfterHook") != "" {
							return callResponsePointer(map[string]any{"after": "test"}), nil
						}
						return nil, nil
					},
				},
				{
					Matcher: func(ctx *engine.Context) (bool, error) { return ctx.Path() == "/test/cookies", nil },
					Handler: func(ctx *engine.Context, _ contract.Response) (*contract.Response, error) {
						if callQuery(ctx).Get("testAfterHook") != "" {
							ctx.AddSetCookie("after=test")
						}
						return nil, nil
					},
				},
				{
					Matcher: func(ctx *engine.Context) (bool, error) {
						message := callQuery(ctx).Get("message")
						return ctx.Path() == "/test/throw" && (message == "throw-after-hook" || message == "throw-chained-hook"), nil
					},
					Handler: func(ctx *engine.Context, _ contract.Response) (*contract.Response, error) {
						message := callQuery(ctx).Get("message")
						if message == "throw-chained-hook" {
							return nil, contract.NewAPIError(http.StatusBadRequest, "BAD_REQUEST", "from chained hook 1")
						}
						_, returnedErr, returned := ctx.Returned()
						if _, typed := contract.AsAPIError(returnedErr); returned && typed {
							return nil, contract.NewAPIError(http.StatusBadRequest, "BAD_REQUEST", "from after hook")
						}
						return nil, nil
					},
				},
				{
					Matcher: func(ctx *engine.Context) (bool, error) {
						return ctx.Path() == "/test/throw" && callQuery(ctx).Get("message") == "throw-chained-hook", nil
					},
					Handler: func(ctx *engine.Context, _ contract.Response) (*contract.Response, error) {
						_, returnedErr, returned := ctx.Returned()
						typed, ok := contract.AsAPIError(returnedErr)
						if !returned || !ok {
							return nil, nil
						}
						return nil, contract.NewAPIError(
							http.StatusBadRequest,
							"BAD_REQUEST",
							strings.Replace(typed.Message, "1", "2", 1),
						)
					},
				},
			},
		},
	}

	auth, err := singleauth.New(singleauth.Options{
		BaseURL:          "http://localhost:3000",
		Secret:           "0123456789abcdef0123456789abcdef",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
		Plugins:          []engine.Plugin{plugin},
		PluginFactories:  []singleauth.PluginFactory{bearer.NewFactory(bearer.Options{})},
		Hooks: engine.Hooks{
			Before: []engine.BeforeHook{{Handler: callGlobalBeforeHook}},
			After: []engine.AfterHook{{Handler: func(ctx *engine.Context, _ contract.Response) (*contract.Response, error) {
				if callQuery(ctx).Get("testAfterGlobal") != "" {
					return callResponsePointer(map[string]any{"after": "global"}), nil
				}
				return nil, nil
			}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func callGlobalBeforeHook(ctx *engine.Context) (*contract.Response, error) {
	if callQuery(ctx).Get("testBeforeGlobal") != "" {
		return callResponsePointer(map[string]any{"before": "global"}), nil
	}
	if ctx.Path() != "/sign-up/email" {
		return nil, nil
	}
	request := ctx.Request()
	var body map[string]any
	if err := json.Unmarshal(request.Body(), &body); err != nil {
		return nil, err
	}
	body["email"] = "changed@email.com"
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	ctx.ReplaceRequest(request.WithBody(encoded))
	return nil, nil
}

func callThrowHandler(ctx *engine.Context) (contract.Response, error) {
	message := callQuery(ctx).Get("message")
	switch message {
	case "throw-api-error":
		return contract.Response{}, contract.NewAPIError(http.StatusBadRequest, "BAD_REQUEST", "Test error")
	case "throw-error":
		return contract.Response{}, errors.New("Test error")
	case "throw redirect":
		return contract.Response{}, contract.NewAPIError(http.StatusFound, "FOUND", "Found").WithHeaders(
			contract.NewHeaders(contract.HeaderField{Name: "Location", Value: "/test"}),
		)
	case "redirect with additional header":
		return contract.Response{}, contract.NewAPIError(http.StatusFound, "FOUND", "Found").WithHeaders(
			contract.NewHeaders(
				contract.HeaderField{Name: "Location", Value: "/test"},
				contract.HeaderField{Name: "key", Value: "value"},
			),
		)
	default:
		return contract.Response{}, contract.NewAPIError(http.StatusBadRequest, "BAD_REQUEST", message)
	}
}

func callQuery(ctx *engine.Context) url.Values {
	query, err := ctx.Request().Query()
	if err != nil {
		return url.Values{}
	}
	return query
}

func callResponsePointer(value any) *contract.Response {
	response, err := contract.JSONResponse(http.StatusOK, value)
	if err != nil {
		panic(err)
	}
	return &response
}

type callExchange func(method, target string, body []byte) (int, http.Header, []byte, error)

type callTransportProfile struct {
	name     string
	exchange callExchange
}

func callTransportProfiles(t *testing.T, auth *singleauth.Auth) []callTransportProfile {
	t.Helper()
	netHTTP := func(method, target string, body []byte) (int, http.Header, []byte, error) {
		request := httptest.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		auth.ServeHTTP(recorder, request)
		response := recorder.Result()
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Clone(), encoded, err
	}

	fastHandler := fasthttptransport.NewHandler(auth.Dispatcher())
	fastHTTP := func(method, target string, body []byte) (int, http.Header, []byte, error) {
		var request fasthttpserver.Request
		request.Header.SetMethod(method)
		request.SetRequestURI(target)
		request.Header.SetHost("localhost:3000")
		if len(body) > 0 {
			request.Header.SetContentType("application/json")
			request.SetBody(body)
		}
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(&request, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123}, nil)
		fastHandler(&requestContext)
		headers := make(http.Header)
		requestContext.Response.Header.VisitAll(func(name, value []byte) {
			headers.Add(string(name), string(value))
		})
		return requestContext.Response.StatusCode(), headers, append([]byte(nil), requestContext.Response.Body()...), nil
	}

	fiberApp := fiberframework.New()
	fiberApp.Use(fibertransport.NewHandler(auth.Dispatcher()))
	fiber := func(method, target string, body []byte) (int, http.Header, []byte, error) {
		request, err := http.NewRequest(method, "http://localhost:3000"+target, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, err
		}
		if len(body) > 0 {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := fiberApp.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			return 0, nil, nil, err
		}
		defer response.Body.Close()
		encoded, err := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Clone(), encoded, err
	}

	return []callTransportProfile{
		{name: "net-http", exchange: netHTTP},
		{name: "fasthttp", exchange: fastHTTP},
		{name: "fiber", exchange: fiber},
	}
}
