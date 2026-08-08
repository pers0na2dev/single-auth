package singleauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"
	fasthttpserver "github.com/valyala/fasthttp"

	singleauth "github.com/pers0na2dev/single-auth"
	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/observability/instrumentation"
	"github.com/pers0na2dev/single-auth/plugins/bearer"
	fasthttptransport "github.com/pers0na2dev/single-auth/transport/fasthttp"
	fibertransport "github.com/pers0na2dev/single-auth/transport/fiber"
	nethttptransport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

type endpointInstrumentationCase struct {
	Suite       string
	Title       string
	Observation endpointInstrumentationObservation
}

type endpointInstrumentationObservation struct {
	Spans []endpointInstrumentationSpan `json:"spans"`
}

type endpointInstrumentationSpan struct {
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

type endpointInstrumentationRecordedSpan struct {
	endpointInstrumentationSpan
	ParentName string
}

type endpointInstrumentationSpanEvent struct {
	Kind string
	Name string
}

func TestEndpointInstrumentationHTTPBehavior(t *testing.T) {
	auth := endpointInstrumentationAuth(t)

	for _, testCase := range endpointInstrumentationCases() {
		testCase := testCase
		t.Run(testCase.Suite+"::"+testCase.Title, func(t *testing.T) {
			for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
				transportName := transportName
				t.Run(transportName, func(t *testing.T) {
					provider := &endpointInstrumentationRecordingProvider{}
					restore := instrumentation.SetTracerProvider(provider)
					defer restore()

					target := "/api/auth/get-session"
					if testCase.Title == "uses the route template for http.route on parameterized endpoints" {
						target = "/api/auth/route-with-params/acme-segment"
					}
					if status := endpointInstrumentationRequest(
						t, transportName, auth.Dispatcher(), target,
					); status != http.StatusOK {
						t.Fatalf("request status = %d, want %d", status, http.StatusOK)
					}

					actual := endpointInstrumentationSelectSpans(
						t, provider.Finished(), testCase.Observation.Spans,
					)
					assertEndpointInstrumentationSpans(
						t, actual, testCase.Observation.Spans,
					)
				})
			}
		})
	}
}

func TestEndpointInstrumentationContextPropagationAcrossPipeline(t *testing.T) {
	auth := endpointInstrumentationAuth(t)
	for _, transportName := range []string{"net-http", "fasthttp", "fiber"} {
		transportName := transportName
		t.Run(transportName, func(t *testing.T) {
			provider := &endpointInstrumentationRecordingProvider{}
			restore := instrumentation.SetTracerProvider(provider)
			defer restore()

			for _, target := range []string{
				"/api/auth/get-session",
				"/api/auth/route-with-params/acme-segment",
			} {
				if status := endpointInstrumentationRequest(
					t, transportName, auth.Dispatcher(), target,
				); status != http.StatusOK {
					t.Fatalf("request %s status = %d, want %d", target, status, http.StatusOK)
				}
			}
			finished := provider.Finished()
			assertEndpointInstrumentationContextPropagation(t, finished)
			assertEndpointInstrumentationMiddlewareLifetime(t, provider.Events())
		})
	}
}

func endpointInstrumentationAuth(t *testing.T) *singleauth.Auth {
	t.Helper()
	testPlugin := engine.Plugin{
		ID: "test-plugin",
		Endpoints: []engine.Endpoint{{
			Name: "routeWithParams", Path: "/route-with-params/:slug",
			Methods: []string{http.MethodGet}, OperationID: "routeWithParams",
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.JSONResponse(http.StatusOK, map[string]any{"ok": true})
			},
		}},
		Middleware: []engine.Middleware{{
			Path: "/**",
			Handler: func(_ *engine.Context, next engine.Next) (contract.Response, error) {
				return next()
			},
		}},
		OnRequest: func(*engine.Context) (engine.OnRequestResult, error) {
			return engine.OnRequestResult{}, nil
		},
		OnResponse: func(*engine.Context, contract.Response) (*contract.Response, error) {
			return nil, nil
		},
	}

	auth, err := singleauth.New(singleauth.Options{
		BaseURL:         "http://localhost:3000",
		Plugins:         []engine.Plugin{testPlugin},
		PluginFactories: []singleauth.PluginFactory{bearer.NewFactory(bearer.Options{})},
		Hooks: engine.Hooks{
			Before: []engine.BeforeHook{{
				Handler: func(*engine.Context) (*contract.Response, error) { return nil, nil },
			}},
			After: []engine.AfterHook{{
				Handler: func(*engine.Context, contract.Response) (*contract.Response, error) {
					return nil, nil
				},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func endpointInstrumentationRequest(
	t *testing.T,
	transportName string,
	dispatcher *engine.Dispatcher,
	target string,
) int {
	t.Helper()
	switch transportName {
	case "net-http":
		request := httptest.NewRequest(http.MethodGet, "http://localhost:3000"+target, nil)
		response := httptest.NewRecorder()
		nethttptransport.NewHandler(dispatcher).ServeHTTP(response, request)
		return response.Code
	case "fasthttp":
		var request fasthttpserver.Request
		request.Header.SetMethod(http.MethodGet)
		request.SetRequestURI(target)
		request.Header.SetHost("localhost:3000")
		var requestContext fasthttpserver.RequestCtx
		requestContext.Init(
			&request,
			&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43123},
			nil,
		)
		fasthttptransport.NewHandler(dispatcher)(&requestContext)
		return requestContext.Response.StatusCode()
	case "fiber":
		app := fiberframework.New()
		app.Use(fibertransport.NewHandler(dispatcher))
		request := httptest.NewRequest(http.MethodGet, "http://localhost:3000"+target, nil)
		response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		return response.StatusCode
	default:
		t.Fatalf("unknown transport %q", transportName)
		return 0
	}
}

type endpointInstrumentationContextKey struct{}

type endpointInstrumentationRecordingProvider struct {
	mu       sync.Mutex
	finished []endpointInstrumentationRecordedSpan
	events   []endpointInstrumentationSpanEvent
}

func (provider *endpointInstrumentationRecordingProvider) Tracer(
	scope,
	version string,
) instrumentation.Tracer {
	if scope != instrumentation.InstrumentationScope ||
		version != instrumentation.InstrumentationVersion {
		panic(fmt.Sprintf("unexpected instrumentation scope %s@%s", scope, version))
	}
	return endpointInstrumentationRecordingTracer{provider: provider}
}

func (provider *endpointInstrumentationRecordingProvider) Finished() []endpointInstrumentationRecordedSpan {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	result := make([]endpointInstrumentationRecordedSpan, len(provider.finished))
	for index, span := range provider.finished {
		result[index] = endpointInstrumentationRecordedSpan{
			endpointInstrumentationSpan: endpointInstrumentationSpan{
				Name: span.Name, Attributes: cloneEndpointInstrumentationAttributes(span.Attributes),
			},
			ParentName: span.ParentName,
		}
	}
	return result
}

func (provider *endpointInstrumentationRecordingProvider) Events() []endpointInstrumentationSpanEvent {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return append([]endpointInstrumentationSpanEvent(nil), provider.events...)
}

type endpointInstrumentationRecordingTracer struct {
	provider *endpointInstrumentationRecordingProvider
}

func (tracer endpointInstrumentationRecordingTracer) Start(
	ctx context.Context,
	name string,
	attributes map[string]any,
) (context.Context, instrumentation.Span) {
	parentName, _ := ctx.Value(endpointInstrumentationContextKey{}).(string)
	tracer.provider.mu.Lock()
	tracer.provider.events = append(tracer.provider.events, endpointInstrumentationSpanEvent{
		Kind: "start", Name: name,
	})
	tracer.provider.mu.Unlock()
	span := &endpointInstrumentationRecordingSpan{
		provider: tracer.provider, name: name, parentName: parentName,
		attributes: cloneEndpointInstrumentationAttributes(attributes),
	}
	return context.WithValue(ctx, endpointInstrumentationContextKey{}, name), span
}

type endpointInstrumentationRecordingSpan struct {
	provider   *endpointInstrumentationRecordingProvider
	name       string
	parentName string
	attributes map[string]any
	mu         sync.Mutex
	ended      bool
}

func (span *endpointInstrumentationRecordingSpan) End() {
	span.mu.Lock()
	if span.ended {
		span.mu.Unlock()
		return
	}
	span.ended = true
	snapshot := endpointInstrumentationRecordedSpan{
		endpointInstrumentationSpan: endpointInstrumentationSpan{
			Name: span.name, Attributes: cloneEndpointInstrumentationAttributes(span.attributes),
		},
		ParentName: span.parentName,
	}
	span.mu.Unlock()

	span.provider.mu.Lock()
	span.provider.finished = append(span.provider.finished, snapshot)
	span.provider.events = append(span.provider.events, endpointInstrumentationSpanEvent{
		Kind: "end", Name: snapshot.Name,
	})
	span.provider.mu.Unlock()
}

func (span *endpointInstrumentationRecordingSpan) SetAttribute(key string, value any) {
	span.mu.Lock()
	span.attributes[key] = value
	span.mu.Unlock()
}

func (*endpointInstrumentationRecordingSpan) SetStatus(any)       {}
func (*endpointInstrumentationRecordingSpan) RecordException(any) {}

func (span *endpointInstrumentationRecordingSpan) UpdateName(name string) instrumentation.Span {
	span.mu.Lock()
	span.name = name
	span.mu.Unlock()
	return span
}

func cloneEndpointInstrumentationAttributes(attributes map[string]any) map[string]any {
	clone := make(map[string]any, len(attributes))
	for key, value := range attributes {
		clone[key] = value
	}
	return clone
}

func endpointInstrumentationSelectSpans(
	t *testing.T,
	finished []endpointInstrumentationRecordedSpan,
	expected []endpointInstrumentationSpan,
) []endpointInstrumentationSpan {
	t.Helper()
	result := make([]endpointInstrumentationSpan, 0, len(expected))
	for _, target := range expected {
		found := false
		for _, span := range finished {
			if span.Name != target.Name {
				continue
			}
			result = append(result, endpointInstrumentationSpan{
				Name: span.Name, Attributes: cloneEndpointInstrumentationAttributes(span.Attributes),
			})
			found = true
			break
		}
		if !found {
			t.Fatalf("span %q not found in %#v", target.Name, finished)
		}
	}
	return result
}

func assertEndpointInstrumentationSpans(
	t *testing.T,
	actual,
	expected []endpointInstrumentationSpan,
) {
	t.Helper()
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualJSON, expectedJSON) {
		t.Fatalf("endpoint instrumentation spans:\n%s\nwant:\n%s", actualJSON, expectedJSON)
	}
}

func assertEndpointInstrumentationContextPropagation(
	t *testing.T,
	finished []endpointInstrumentationRecordedSpan,
) {
	t.Helper()
	roots := []string{
		"onRequest test-plugin",
		"middleware /** test-plugin",
		"GET /get-session",
		"onResponse test-plugin",
		"GET /route-with-params/:slug",
	}
	for _, name := range roots {
		found := false
		for _, span := range finished {
			if span.Name != name {
				continue
			}
			found = true
			if span.ParentName != "" {
				t.Fatalf("root span %q parent = %q, want empty", name, span.ParentName)
			}
			break
		}
		if !found {
			t.Fatalf("root span %q not found", name)
		}
	}

	parents := map[string]string{
		"handler /get-session":                              "GET /get-session",
		"hook before /get-session user":                     "GET /get-session",
		"hook after /get-session user":                      "GET /get-session",
		"hook after /get-session plugin:bearer":             "GET /get-session",
		"handler /route-with-params/:slug":                  "GET /route-with-params/:slug",
		"hook before /route-with-params/:slug user":         "GET /route-with-params/:slug",
		"hook after /route-with-params/:slug user":          "GET /route-with-params/:slug",
		"hook after /route-with-params/:slug plugin:bearer": "GET /route-with-params/:slug",
	}
	for child, expectedParent := range parents {
		found := false
		for _, span := range finished {
			if span.Name != child {
				continue
			}
			found = true
			if span.ParentName != expectedParent {
				t.Fatalf("span %q parent = %q, want %q", child, span.ParentName, expectedParent)
			}
			break
		}
		if !found {
			t.Fatalf("context propagation span %q not found", child)
		}
	}
}

func assertEndpointInstrumentationMiddlewareLifetime(
	t *testing.T,
	events []endpointInstrumentationSpanEvent,
) {
	t.Helper()
	for _, endpointName := range []string{
		"GET /get-session",
		"GET /route-with-params/:slug",
	} {
		endpointStart := -1
		for index, event := range events {
			if event.Kind == "start" && event.Name == endpointName {
				endpointStart = index
				break
			}
		}
		if endpointStart < 0 {
			t.Fatalf("endpoint start event %q not found in %#v", endpointName, events)
		}

		middlewareEnd := -1
		for index := endpointStart - 1; index >= 0; index-- {
			event := events[index]
			if event.Kind == "end" && event.Name == "middleware /** test-plugin" {
				middlewareEnd = index
				break
			}
		}
		if middlewareEnd < 0 {
			t.Fatalf("middleware did not end before endpoint %q: %#v", endpointName, events)
		}
	}
}

func TestEndpointInstrumentationScenarioDefinitions(t *testing.T) {
	cases := endpointInstrumentationCases()
	if len(cases) != 8 {
		t.Fatalf("endpoint instrumentation scenarios=%d, want 8", len(cases))
	}
	seen := make(map[string]struct{}, len(cases))
	for _, testCase := range cases {
		name := testCase.Suite + "::" + testCase.Title
		if testCase.Suite != "endpoints instrumentation" || testCase.Title == "" ||
			len(testCase.Observation.Spans) == 0 {
			t.Fatalf("invalid endpoint instrumentation scenario: %#v", testCase)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate endpoint instrumentation scenario %q", name)
		}
		seen[name] = struct{}{}
	}
}

func endpointInstrumentationCases() []endpointInstrumentationCase {
	span := func(name string, attributes map[string]any) endpointInstrumentationObservation {
		return endpointInstrumentationObservation{Spans: []endpointInstrumentationSpan{{Name: name, Attributes: attributes}}}
	}
	return []endpointInstrumentationCase{
		{Suite: "endpoints instrumentation", Title: "emits a parent span for each endpoint", Observation: span("GET /get-session", map[string]any{
			"single_auth.operation_id": "getSession", "http.route": "/get-session",
		})},
		{Suite: "endpoints instrumentation", Title: "emits a span for each middleware", Observation: span("middleware /** test-plugin", map[string]any{
			"single_auth.context": "plugin:test-plugin", "single_auth.hook.type": "middleware", "http.route": "/**",
		})},
		{Suite: "endpoints instrumentation", Title: "emits a span for onRequest hooks", Observation: span("onRequest test-plugin", map[string]any{
			"single_auth.context": "plugin:test-plugin", "single_auth.hook.type": "onRequest",
		})},
		{Suite: "endpoints instrumentation", Title: "emits a span for onResponse hooks", Observation: span("onResponse test-plugin", map[string]any{
			"single_auth.context": "plugin:test-plugin", "single_auth.hook.type": "onResponse", "http.response.status_code": 200,
		})},
		{Suite: "endpoints instrumentation", Title: "emits a span for the endpoint handler", Observation: span("handler /get-session", map[string]any{
			"single_auth.operation_id": "getSession", "http.route": "/get-session",
		})},
		{Suite: "endpoints instrumentation", Title: "emits spans for global hooks", Observation: endpointInstrumentationObservation{Spans: []endpointInstrumentationSpan{
			{Name: "hook before /get-session user", Attributes: map[string]any{"single_auth.context": "user", "single_auth.hook.type": "before", "single_auth.operation_id": "getSession", "http.route": "/get-session"}},
			{Name: "hook after /get-session user", Attributes: map[string]any{"single_auth.context": "user", "single_auth.hook.type": "after", "single_auth.operation_id": "getSession", "http.route": "/get-session"}},
		}}},
		{Suite: "endpoints instrumentation", Title: "emits spans for plugin-originated hooks", Observation: span("hook after /get-session plugin:bearer", map[string]any{
			"single_auth.context": "plugin:bearer", "single_auth.hook.type": "after", "single_auth.operation_id": "getSession", "http.route": "/get-session",
		})},
		{Suite: "endpoints instrumentation", Title: "uses the route template for http.route on parameterized endpoints", Observation: span("GET /route-with-params/:slug", map[string]any{
			"single_auth.operation_id": "routeWithParams", "http.route": "/route-with-params/:slug",
		})},
	}
}
