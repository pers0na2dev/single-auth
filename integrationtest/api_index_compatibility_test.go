package singleauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/storage"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type apiIndexCase struct {
	Suite       string
	Title       string
	Observation any
}

type apiIndexExchangeInput struct {
	Context context.Context
	Method  string
	Target  string
	Body    []byte
}

type apiIndexExchangeResponse struct {
	Status int
	Body   []byte
}

type apiIndexExchange func(apiIndexExchangeInput) (apiIndexExchangeResponse, error)

func TestAPIIndexHTTPRuntimeBehavior(t *testing.T) {
	for _, vector := range apiIndexCases() {
		vector := vector
		t.Run(vector.Suite+"::"+vector.Title, func(t *testing.T) {
			if vector.Suite == "getEndpoints" {
				actual := runAPIIndexInitializedContext(t)
				assertAPIIndexObservation(t, actual, vector.Observation)
				return
			}
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					actual := runAPIIndexHTTPVector(t, vector.Suite, vector.Title, transportName)
					assertAPIIndexObservation(t, actual, vector.Observation)
				})
			}
		})
	}
}

func runAPIIndexHTTPVector(t *testing.T, suite, title, transportName string) any {
	t.Helper()
	options := singleauth.Options{
		BaseURL:          "http://localhost:3000",
		EmailAndPassword: singleauth.EmailAndPasswordOptions{Enabled: true},
	}

	var order []string
	var receivedHeader string
	switch suite + "::" + title {
	case "onRequest chain::should execute all plugins onRequest handlers in chain":
		options.Plugins = []engine.Plugin{
			{
				ID: "plugin-a",
				OnRequest: func(ctx *engine.Context) (engine.OnRequestResult, error) {
					order = append(order, "plugin-a")
					request := ctx.Request().WithHeader("x-plugin-a", "true")
					return engine.OnRequestResult{Request: &request}, nil
				},
			},
			{
				ID: "plugin-b",
				OnRequest: func(ctx *engine.Context) (engine.OnRequestResult, error) {
					order = append(order, "plugin-b")
					if value, _ := ctx.Request().Headers().Get("x-plugin-a"); value != "true" {
						return engine.OnRequestResult{}, errors.New("plugin-b did not receive plugin-a request")
					}
					request := ctx.Request().WithHeader("x-plugin-b", "true")
					return engine.OnRequestResult{Request: &request}, nil
				},
			},
			{
				ID: "plugin-c",
				OnRequest: func(ctx *engine.Context) (engine.OnRequestResult, error) {
					order = append(order, "plugin-c")
					if value, _ := ctx.Request().Headers().Get("x-plugin-b"); value != "true" {
						return engine.OnRequestResult{}, errors.New("plugin-c did not receive plugin-b request")
					}
					return engine.OnRequestResult{}, nil
				},
			},
		}
	case "onRequest chain::should pass modified request from previous plugin to next plugin":
		options.Plugins = []engine.Plugin{
			{
				ID: "plugin-a",
				OnRequest: func(ctx *engine.Context) (engine.OnRequestResult, error) {
					request := ctx.Request().WithHeader("x-from-plugin-a", "hello")
					return engine.OnRequestResult{Request: &request}, nil
				},
			},
			{
				ID: "plugin-b",
				OnRequest: func(ctx *engine.Context) (engine.OnRequestResult, error) {
					receivedHeader, _ = ctx.Request().Headers().Get("x-from-plugin-a")
					return engine.OnRequestResult{}, nil
				},
			},
		}
	case "onRequest chain::should stop chain when response is returned":
		options.Plugins = []engine.Plugin{
			{
				ID: "plugin-a",
				OnRequest: func(*engine.Context) (engine.OnRequestResult, error) {
					order = append(order, "plugin-a")
					response := contract.TextResponse(http.StatusForbidden, "Blocked by plugin-a")
					return engine.OnRequestResult{Response: &response}, nil
				},
			},
			{
				ID: "plugin-b",
				OnRequest: func(*engine.Context) (engine.OnRequestResult, error) {
					order = append(order, "plugin-b")
					response := contract.TextResponse(http.StatusOK, "ok")
					return engine.OnRequestResult{Response: &response}, nil
				},
			},
		}
	case "skipTrailingSlashes option::should handle trailing slash requests when skipTrailingSlashes is enabled",
		"skipTrailingSlashes option::should work with POST requests with trailing slash":
		options.Advanced.SkipTrailingSlashes = true
	case "base path leading-prefix enforcement::rejects a path where basePath is not a leading prefix":
		options.BasePath = "/api/auth"
	case "base path leading-prefix enforcement::rejects a path before basePath that targets a disabled route":
		options.BasePath = "/api/auth"
		options.DisabledPaths = []string{"/sign-up/email"}
	}

	auth, err := singleauth.New(options)
	if err != nil {
		t.Fatal(err)
	}
	if suite == "onRequest chain" {
		if _, err := auth.API().SignUpEmail(t.Context(), singleauth.SignUpEmailInput{
			Name: "test user", Email: "test@test.com", Password: "test123456",
		}); err != nil {
			t.Fatal(err)
		}
	}
	exchange := newAPIIndexExchange(t, transportName, auth.Dispatcher())
	request := func(method, target string, body []byte) apiIndexExchangeResponse {
		t.Helper()
		response, exchangeErr := exchange(apiIndexExchangeInput{
			Context: context.Background(), Method: method, Target: target, Body: body,
		})
		if exchangeErr != nil {
			t.Fatal(exchangeErr)
		}
		return response
	}

	switch suite + "::" + title {
	case "onRequest chain::should execute all plugins onRequest handlers in chain":
		response := request(
			http.MethodPost,
			"/api/auth/sign-in/email",
			[]byte(`{"email":"test@test.com","password":"test123456"}`),
		)
		return map[string]any{"order": order, "status": response.Status}
	case "onRequest chain::should pass modified request from previous plugin to next plugin":
		response := request(
			http.MethodPost,
			"/api/auth/sign-in/email",
			[]byte(`{"email":"test@test.com","password":"test123456"}`),
		)
		return map[string]any{"receivedHeader": receivedHeader, "status": response.Status}
	case "onRequest chain::should stop chain when response is returned":
		response := request(
			http.MethodPost,
			"/api/auth/sign-in/email",
			[]byte(`{"email":"test@test.com","password":"test123456"}`),
		)
		return map[string]any{
			"order": order, "status": response.Status, "body": string(response.Body),
		}
	case "skipTrailingSlashes option::should return 404 for trailing slash requests by default":
		response := request(http.MethodGet, "/api/auth/ok/", nil)
		return map[string]any{"status": response.Status}
	case "skipTrailingSlashes option::should handle trailing slash requests when skipTrailingSlashes is enabled":
		response := request(http.MethodGet, "/api/auth/ok/", nil)
		var body map[string]any
		if err := json.Unmarshal(response.Body, &body); err != nil {
			t.Fatal(err)
		}
		return map[string]any{"status": response.Status, "body": body}
	case "skipTrailingSlashes option::should work with POST requests with trailing slash":
		body := []byte(`{"email":"test2@example.com","password":"password123","name":"Test User 2"}`)
		response := request(http.MethodPost, "/api/auth/sign-up/email/", body)
		return map[string]any{
			"status": response.Status, "notFound": response.Status == http.StatusNotFound,
		}
	case "base path leading-prefix enforcement::rejects a path where basePath is not a leading prefix":
		response := request(http.MethodGet, "/x/api/auth/ok", nil)
		return map[string]any{"status": response.Status}
	case "base path leading-prefix enforcement::rejects a path before basePath that targets a disabled route":
		body := []byte(`{"email":"user@example.com","password":"password12345","name":"Test User"}`)
		blocked := request(http.MethodPost, "/api/auth/sign-up/email", body)
		confused := request(http.MethodPost, "/x/api/auth/sign-up/email", body)
		return map[string]any{
			"blockedStatus": blocked.Status, "confusedStatus": confused.Status,
		}
	default:
		t.Fatalf("unsupported API index vector %q::%q", suite, title)
		return nil
	}
}

type apiIndexContextKey struct{}

type apiIndexInitializationFactory struct {
	started     chan struct{}
	release     chan struct{}
	initialized atomic.Bool
	called      atomic.Bool

	mu         sync.Mutex
	baseURL    string
	customProp string
}

func (factory *apiIndexInitializationFactory) PluginID() string { return "context-probe" }

func (factory *apiIndexInitializationFactory) Schema() (storage.Schema, error) {
	return storage.Schema{}, nil
}

func (factory *apiIndexInitializationFactory) Build(
	host singleauth.PluginHost,
) (engine.Plugin, error) {
	close(factory.started)
	<-factory.release
	if host.Options.BaseURL != "http://localhost:3000" ||
		host.Options.BasePath != "/api/auth" ||
		len(host.Options.Schema.Models) == 0 {
		return engine.Plugin{}, errors.New("plugin host options were not initialized")
	}
	factory.mu.Lock()
	factory.baseURL = host.Options.BaseURL
	factory.mu.Unlock()
	factory.initialized.Store(true)
	return engine.Plugin{
		ID: "context-probe",
		Middleware: []engine.Middleware{{
			Path: "/test",
			Handler: func(ctx *engine.Context, next engine.Next) (contract.Response, error) {
				if !factory.initialized.Load() {
					return contract.Response{}, errors.New("middleware ran before plugin initialization")
				}
				customProp, _ := ctx.GoContext().Value(apiIndexContextKey{}).(string)
				factory.mu.Lock()
				factory.customProp = customProp
				factory.mu.Unlock()
				factory.called.Store(true)
				return next()
			},
		}},
	}, nil
}

func runAPIIndexInitializedContext(t *testing.T) any {
	t.Helper()
	factory := &apiIndexInitializationFactory{
		started: make(chan struct{}), release: make(chan struct{}),
	}
	type result struct {
		auth *singleauth.Auth
		err  error
	}
	constructed := make(chan result, 1)
	go func() {
		auth, err := singleauth.New(singleauth.Options{
			BaseURL:         "http://localhost:3000",
			PluginFactories: []singleauth.PluginFactory{factory},
			Endpoints: []engine.Endpoint{{
				Name: "contextProbe", Path: "/test", Methods: []string{http.MethodGet},
				Handler: func(*engine.Context) (contract.Response, error) {
					return contract.JSONResponse(http.StatusOK, map[string]any{"ok": true})
				},
			}},
		})
		constructed <- result{auth: auth, err: err}
	}()

	select {
	case <-factory.started:
	case <-time.After(2 * time.Second):
		t.Fatal("plugin initialization did not start")
	}
	calledBeforeResolution := false
	select {
	case early := <-constructed:
		calledBeforeResolution = true
		if early.err != nil {
			t.Fatal(early.err)
		}
	default:
	}
	close(factory.release)

	var initialized result
	select {
	case initialized = <-constructed:
	case <-time.After(2 * time.Second):
		t.Fatal("auth initialization did not complete")
	}
	if initialized.err != nil {
		t.Fatal(initialized.err)
	}
	requestContext := context.WithValue(context.Background(), apiIndexContextKey{}, "value")
	exchange := newAPIIndexExchange(t, "net-http", initialized.auth.Dispatcher())
	response, err := exchange(apiIndexExchangeInput{
		Context: requestContext, Method: http.MethodGet, Target: "/api/auth/test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK {
		t.Fatalf("initialized middleware response=%d body=%s", response.Status, response.Body)
	}
	factory.mu.Lock()
	baseURL, customProp := factory.baseURL, factory.customProp
	factory.mu.Unlock()
	return map[string]any{
		"calledBeforeResolution": calledBeforeResolution,
		"middlewareCalled":       factory.called.Load(),
		"baseURL":                baseURL,
		"optionsReady":           factory.initialized.Load(),
		"customProp":             customProp,
	}
}

func newAPIIndexExchange(
	t *testing.T,
	transportName string,
	dispatcher *engine.Dispatcher,
) apiIndexExchange {
	t.Helper()
	switch transportName {
	case "net-http":
		handler := nethttptransport.NewHandler(dispatcher)
		return func(input apiIndexExchangeInput) (apiIndexExchangeResponse, error) {
			request := httptest.NewRequest(
				input.Method,
				"http://localhost:3000"+input.Target,
				bytes.NewReader(input.Body),
			)
			if input.Context != nil {
				request = request.WithContext(input.Context)
			}
			if len(input.Body) > 0 {
				request.Header.Set("Content-Type", "application/json")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			return apiIndexExchangeResponse{Status: response.StatusCode, Body: body}, err
		}
	case "fasthttp":
		type contextKey struct{}
		key := contextKey{}
		handler := fasthttptransport.NewHandler(
			dispatcher,
			fasthttptransport.WithContextProvider(
				func(ctx *fasthttpserver.RequestCtx) context.Context {
					requestContext, _ := ctx.UserValue(key).(context.Context)
					return requestContext
				},
			),
		)
		return func(input apiIndexExchangeInput) (apiIndexExchangeResponse, error) {
			var request fasthttpserver.Request
			request.Header.SetMethod(input.Method)
			request.Header.SetHost("localhost:3000")
			request.SetRequestURI(input.Target)
			request.SetBody(input.Body)
			if len(input.Body) > 0 {
				request.Header.SetContentType("application/json")
			}
			var requestContext fasthttpserver.RequestCtx
			requestContext.Init(
				&request,
				&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
				nil,
			)
			requestContext.SetUserValue(key, input.Context)
			handler(&requestContext)
			return apiIndexExchangeResponse{
				Status: requestContext.Response.StatusCode(),
				Body:   append([]byte(nil), requestContext.Response.Body()...),
			}, nil
		}
	case "fiber":
		return func(input apiIndexExchangeInput) (apiIndexExchangeResponse, error) {
			app := fiberframework.New()
			app.Use(func(ctx fiberframework.Ctx) error {
				if input.Context != nil {
					ctx.SetContext(input.Context)
				}
				return ctx.Next()
			})
			app.Use(fibertransport.NewHandler(dispatcher))
			request, err := http.NewRequest(
				input.Method,
				"http://localhost:3000"+input.Target,
				bytes.NewReader(input.Body),
			)
			if err != nil {
				return apiIndexExchangeResponse{}, err
			}
			if len(input.Body) > 0 {
				request.Header.Set("Content-Type", "application/json")
			}
			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return apiIndexExchangeResponse{}, err
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			return apiIndexExchangeResponse{Status: response.StatusCode, Body: body}, err
		}
	default:
		t.Fatalf("unknown API index transport %q", transportName)
		return nil
	}
}

func assertAPIIndexObservation(t *testing.T, actual any, expected any) {
	t.Helper()
	encoded, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	var normalizedActual, normalizedExpected any
	if err := json.Unmarshal(encoded, &normalizedActual); err != nil {
		t.Fatal(err)
	}
	expectedEncoded, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expectedEncoded, &normalizedExpected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalizedActual, normalizedExpected) {
		t.Fatalf("API index observation=%s want=%s", encoded, expectedEncoded)
	}
}

func TestAPIIndexScenarioDefinitions(t *testing.T) {
	cases := apiIndexCases()
	if len(cases) != 9 {
		t.Fatalf("API index scenarios=%d, want 9", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, vector := range cases {
		name := vector.Suite + "::" + vector.Title
		if vector.Suite == "" || vector.Title == "" || vector.Observation == nil {
			t.Fatalf("invalid API index scenario: %#v", vector)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate API index scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func apiIndexCases() []apiIndexCase {
	return []apiIndexCase{
		{Suite: "base path leading-prefix enforcement", Title: "rejects a path before basePath that targets a disabled route", Observation: map[string]any{"blockedStatus": 404, "confusedStatus": 404}},
		{Suite: "base path leading-prefix enforcement", Title: "rejects a path where basePath is not a leading prefix", Observation: map[string]any{"status": 404}},
		{Suite: "getEndpoints", Title: "should await promise-based context before passing to middleware", Observation: map[string]any{"calledBeforeResolution": false, "middlewareCalled": true, "baseURL": "http://localhost:3000", "optionsReady": true, "customProp": "value"}},
		{Suite: "onRequest chain", Title: "should execute all plugins onRequest handlers in chain", Observation: map[string]any{"order": []string{"plugin-a", "plugin-b", "plugin-c"}, "status": 200}},
		{Suite: "onRequest chain", Title: "should pass modified request from previous plugin to next plugin", Observation: map[string]any{"receivedHeader": "hello", "status": 200}},
		{Suite: "onRequest chain", Title: "should stop chain when response is returned", Observation: map[string]any{"order": []string{"plugin-a"}, "status": 403, "body": "Blocked by plugin-a"}},
		{Suite: "skipTrailingSlashes option", Title: "should handle trailing slash requests when skipTrailingSlashes is enabled", Observation: map[string]any{"status": 200, "body": map[string]any{"ok": true}}},
		{Suite: "skipTrailingSlashes option", Title: "should return 404 for trailing slash requests by default", Observation: map[string]any{"status": 404}},
		{Suite: "skipTrailingSlashes option", Title: "should work with POST requests with trailing slash", Observation: map[string]any{"status": 200, "notFound": false}},
	}
}
