package engine

import (
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func responsePointer(response contract.Response) *contract.Response { return &response }

func requestPointer(request contract.Request) *contract.Request { return &request }

func TestDispatchPipelineOrderAndHeaders(t *testing.T) {
	var events []string
	record := func(event string) { events = append(events, event) }

	endpoint := Endpoint{
		Name:    "user",
		Path:    "/users/:userID",
		Methods: []string{"GET"},
		Handler: func(ctx *Context) (contract.Response, error) {
			record("endpoint")
			if value, _ := ctx.Request().Headers().Get("X-On-Request"); value != "two" {
				t.Fatalf("endpoint request header = %q, want two", value)
			}
			if userID, _ := ctx.Param("userID"); userID != "a/b" {
				t.Fatalf("userID = %q, want a/b", userID)
			}
			ctx.AddSetCookie("endpoint=1; Path=/")
			return contract.TextResponse(contract.StatusOK, "endpoint").WithHeader("X-Stage", "endpoint"), nil
		},
	}

	plugin := func(id string) Plugin {
		return Plugin{
			ID: id,
			Middleware: []Middleware{{
				Name: "middleware-" + id,
				Path: "/users/:id",
				Handler: func(ctx *Context, next Next) (contract.Response, error) {
					record("middleware:" + id + ":before")
					response, err := next()
					record("middleware:" + id + ":after")
					return response, err
				},
			}},
			Hooks: Hooks{
				Before: []BeforeHook{{
					Name: "before-" + id,
					Matcher: func(ctx *Context) (bool, error) {
						return ctx.Path() == "/users/:userID", nil
					},
					Handler: func(ctx *Context) (*contract.Response, error) {
						record("before:" + id)
						ctx.AddSetCookie("before-" + id + "=1; Path=/")
						return nil, nil
					},
				}},
				After: []AfterHook{{
					Name: "after-" + id,
					Handler: func(ctx *Context, response contract.Response) (*contract.Response, error) {
						record("after:" + id)
						ctx.AddSetCookie("after-" + id + "=1; Path=/")
						return nil, nil
					},
				}},
			},
			OnRequest: func(ctx *Context) (OnRequestResult, error) {
				record("onRequest:" + id)
				request := ctx.Request().WithHeader("X-On-Request", id)
				return OnRequestResult{Request: requestPointer(request)}, nil
			},
			OnResponse: func(ctx *Context, response contract.Response) (*contract.Response, error) {
				record("onResponse:" + id)
				ctx.AddSetCookie("response-" + id + "=1; Path=/")
				return nil, nil
			},
		}
	}

	registry, err := NewRegistry([]Endpoint{endpoint}, plugin("one"), plugin("two"))
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{
		BasePath: "/api/auth",
		Middleware: []Middleware{{
			Name: "user-middleware",
			Path: "/**",
			Handler: func(ctx *Context, next Next) (contract.Response, error) {
				record("middleware:user:before")
				response, err := next()
				record("middleware:user:after")
				return response, err
			},
		}},
		Hooks: Hooks{
			Before: []BeforeHook{{
				Name: "user-before",
				Handler: func(ctx *Context) (*contract.Response, error) {
					record("before:user")
					return nil, nil
				},
			}},
			After: []AfterHook{{
				Name: "user-after",
				Handler: func(ctx *Context, response contract.Response) (*contract.Response, error) {
					record("after:user")
					ctx.SetResponseHeader("X-Stage", "user-after")
					return nil, nil
				},
			}},
		},
	})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	request := contract.NewRequest("GET", "/api/auth/users/a%2Fb", contract.RequestOptions{})
	response, err := dispatcher.Dispatch(request)
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if got, want := events, []string{
		"onRequest:one",
		"onRequest:two",
		"middleware:user:before",
		"middleware:one:before",
		"middleware:two:before",
		"before:user",
		"before:one",
		"before:two",
		"endpoint",
		"after:user",
		"after:one",
		"after:two",
		"middleware:two:after",
		"middleware:one:after",
		"middleware:user:after",
		"onResponse:one",
		"onResponse:two",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pipeline order:\n got  %#v\n want %#v", got, want)
	}
	if got, _ := response.Headers().Get("X-Stage"); got != "user-after" {
		t.Fatalf("X-Stage = %q, want user-after", got)
	}
	if got, want := response.Headers().Values("Set-Cookie"), []string{
		"before-one=1; Path=/",
		"before-two=1; Path=/",
		"endpoint=1; Path=/",
		"after-one=1; Path=/",
		"after-two=1; Path=/",
		"response-one=1; Path=/",
		"response-two=1; Path=/",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Set-Cookie values:\n got  %#v\n want %#v", got, want)
	}
}

func TestOnRequestShortCircuitStillRunsOnResponse(t *testing.T) {
	var events []string
	plugin := Plugin{
		ID: "short",
		OnRequest: func(*Context) (OnRequestResult, error) {
			events = append(events, "onRequest")
			response := contract.TextResponse(418, "short")
			return OnRequestResult{Response: responsePointer(response)}, nil
		},
		OnResponse: func(_ *Context, response contract.Response) (*contract.Response, error) {
			events = append(events, "onResponse")
			updated := response.WithHeader("X-Response", "seen")
			return &updated, nil
		},
		Hooks: Hooks{Before: []BeforeHook{{
			Handler: func(*Context) (*contract.Response, error) {
				events = append(events, "before")
				return nil, nil
			},
		}}},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "never", Path: "/never", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			events = append(events, "endpoint")
			return contract.TextResponse(200, "never"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{Middleware: []Middleware{{
		Path: "/**",
		Handler: func(_ *Context, next Next) (contract.Response, error) {
			events = append(events, "middleware")
			return next()
		},
	}}})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("GET", "/never", contract.RequestOptions{}))
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if got, want := events, []string{"onRequest", "onResponse"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	if response.Status() != 418 || string(response.Body()) != "short" {
		t.Fatalf("response = %d %q", response.Status(), response.Body())
	}
	if got, _ := response.Headers().Get("X-Response"); got != "seen" {
		t.Fatalf("X-Response = %q", got)
	}
}

func TestAfterHookCanRemovePreviouslyAccumulatedHeaderValues(t *testing.T) {
	registry, err := NewRegistry([]Endpoint{{
		Name: "session-cookie", Path: "/session-cookie", Methods: []string{"POST"},
		Handler: func(ctx *Context) (contract.Response, error) {
			ctx.AddSetCookie("session=live; Path=/")
			ctx.AddSetCookie("unrelated=keep; Path=/")
			return contract.TextResponse(contract.StatusOK, "endpoint"), nil
		},
	}}, Plugin{ID: "cookie-scrubber", Hooks: Hooks{After: []AfterHook{{
		Handler: func(ctx *Context, _ contract.Response) (*contract.Response, error) {
			ctx.RemoveResponseHeaderValues("set-cookie", "session=live; Path=/")
			ctx.AddSetCookie("session=; Max-Age=0; Path=/")
			replacement := contract.TextResponse(contract.StatusOK, "replacement")
			return &replacement, nil
		},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Invoke("session-cookie", DirectInput{Request: contract.NewRequest("POST", "/session-cookie", contract.RequestOptions{})})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := response.Headers().Values("Set-Cookie"), []string{
		"unrelated=keep; Path=/",
		"session=; Max-Age=0; Path=/",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Set-Cookie=%#v want=%#v", got, want)
	}
	if string(response.Body()) != "replacement" {
		t.Fatalf("body=%q", response.Body())
	}
}

func TestBeforeHookShortCircuitSkipsEndpointAndAfterHooks(t *testing.T) {
	var events []string
	registry, err := NewRegistry([]Endpoint{{
		Name: "endpoint", Path: "/endpoint", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			events = append(events, "endpoint")
			return contract.TextResponse(200, "endpoint"), nil
		},
	}})
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{Hooks: Hooks{
		Before: []BeforeHook{
			{Handler: func(ctx *Context) (*contract.Response, error) {
				events = append(events, "before-one")
				ctx.AddSetCookie("before=1")
				response := contract.TextResponse(202, "accepted")
				return &response, nil
			}},
			{Handler: func(*Context) (*contract.Response, error) {
				events = append(events, "before-two")
				return nil, nil
			}},
		},
		After: []AfterHook{{Handler: func(_ *Context, response contract.Response) (*contract.Response, error) {
			events = append(events, "after")
			return nil, nil
		}}},
	}})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("GET", "/endpoint", contract.RequestOptions{}))
	if err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}
	if got, want := events, []string{"before-one"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
	if response.Status() != 202 || string(response.Body()) != "accepted" {
		t.Fatalf("response = %d %q", response.Status(), response.Body())
	}
	if got := response.Headers().Values("Set-Cookie"); !reflect.DeepEqual(got, []string{"before=1"}) {
		t.Fatalf("Set-Cookie = %#v", got)
	}
}

func TestDirectServerOnlyDispatchRunsOnlyEndpointHooks(t *testing.T) {
	var events []string
	plugin := Plugin{
		ID: "private",
		Endpoints: []Endpoint{{
			Name: "privateEndpoint", ServerOnly: true,
			Handler: func(*Context) (contract.Response, error) {
				events = append(events, "endpoint")
				return contract.TextResponse(200, "private"), nil
			},
		}},
		Middleware: []Middleware{{
			Path: "/**",
			Handler: func(_ *Context, next Next) (contract.Response, error) {
				events = append(events, "middleware")
				return next()
			},
		}},
		Hooks: Hooks{
			Before: []BeforeHook{{Handler: func(*Context) (*contract.Response, error) {
				events = append(events, "before")
				return nil, nil
			}}},
			After: []AfterHook{{Handler: func(_ *Context, response contract.Response) (*contract.Response, error) {
				events = append(events, "after")
				return nil, nil
			}}},
		},
		OnRequest: func(*Context) (OnRequestResult, error) {
			events = append(events, "onRequest")
			return OnRequestResult{}, nil
		},
		OnResponse: func(_ *Context, response contract.Response) (*contract.Response, error) {
			events = append(events, "onResponse")
			return nil, nil
		},
	}
	registry, err := NewRegistry(nil, plugin)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}

	response, err := dispatcher.Invoke("privateEndpoint", DirectInput{})
	if err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}
	if response.Status() != 200 || string(response.Body()) != "private" {
		t.Fatalf("response = %d %q", response.Status(), response.Body())
	}
	if got, want := events, []string{"before", "endpoint", "after"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("events = %#v, want %#v", got, want)
	}

	response, err = dispatcher.Dispatch(contract.NewRequest("POST", "/private", contract.RequestOptions{}))
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != contract.StatusNotFound || response.Status() != contract.StatusNotFound {
		t.Fatalf("HTTP server-only response = %d, %T %v", response.Status(), err, err)
	}
}

func TestDisabledPathRunsBeforePluginOnRequest(t *testing.T) {
	called := false
	plugin := Plugin{
		ID: "probe",
		OnRequest: func(*Context) (OnRequestResult, error) {
			called = true
			return OnRequestResult{}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "disabled", Path: "/disabled", Methods: []string{"GET"}, Handler: textHandler("disabled"),
	}}, plugin)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{DisabledPaths: []string{"/disabled"}})
	if err != nil {
		t.Fatalf("NewDispatcher() error = %v", err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("GET", "/disabled", contract.RequestOptions{}))
	if called {
		t.Fatal("onRequest ran for a disabled path")
	}
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Status != contract.StatusNotFound || response.Status() != contract.StatusNotFound {
		t.Fatalf("disabled response = %d, %T %v", response.Status(), err, err)
	}
}

func TestCoreOnRequestRunsBeforePluginOnRequestAndCanShortCircuit(t *testing.T) {
	var events []string
	plugin := Plugin{
		ID: "probe",
		OnRequest: func(*Context) (OnRequestResult, error) {
			events = append(events, "plugin")
			return OnRequestResult{}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "target", Path: "/target", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			events = append(events, "endpoint")
			return contract.TextResponse(200, "target"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	block := false
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{
		OnRequest: []OnRequestFunc{func(*Context) (OnRequestResult, error) {
			events = append(events, "core")
			if block {
				response := contract.TextResponse(429, "limited")
				return OnRequestResult{Response: &response}, nil
			}
			return OnRequestResult{}, nil
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := dispatcher.Dispatch(contract.NewRequest("GET", "/target", contract.RequestOptions{}))
	if err != nil || response.Status() != 200 {
		t.Fatalf("first dispatch = %d, %v", response.Status(), err)
	}
	if got, want := events, []string{"core", "plugin", "endpoint"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first order = %#v, want %#v", got, want)
	}

	events = nil
	block = true
	response, err = dispatcher.Dispatch(contract.NewRequest("GET", "/target", contract.RequestOptions{}))
	if err != nil || response.Status() != 429 || string(response.Body()) != "limited" {
		t.Fatalf("limited dispatch = %d %q, %v", response.Status(), response.Body(), err)
	}
	if got, want := events, []string{"core"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("limited order = %#v, want %#v", got, want)
	}
}

func TestOutsideBasePathOnRequestCanShortCircuit(t *testing.T) {
	const outsidePath = "/.well-known/oauth-authorization-server/api/auth"
	plugin := Plugin{
		ID: "outside-short-circuit",
		OnRequest: func(ctx *Context) (OnRequestResult, error) {
			if ctx.RoutePath() != outsidePath || ctx.Request().RawPath() != outsidePath {
				t.Fatalf("outside request paths = route %q raw %q", ctx.RoutePath(), ctx.Request().RawPath())
			}
			response := contract.TextResponse(contract.StatusOK, "metadata")
			return OnRequestResult{Response: &response}, nil
		},
	}
	registry, err := NewRegistry(nil, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("GET", outsidePath, contract.RequestOptions{}))
	if dispatchErr != nil || response.Status() != contract.StatusOK || string(response.Body()) != "metadata" {
		t.Fatalf("outside short-circuit = %d %q, %v", response.Status(), response.Body(), dispatchErr)
	}
}

func TestUnclaimedOutsideBasePathReturnsNotFoundWithoutRouting(t *testing.T) {
	var onRequestCalls, middlewareCalls, endpointCalls int
	plugin := Plugin{
		ID: "outside-unclaimed",
		OnRequest: func(*Context) (OnRequestResult, error) {
			onRequestCalls++
			return OnRequestResult{}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "target", Path: "/target", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			endpointCalls++
			return contract.TextResponse(contract.StatusOK, "target"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{
		BasePath: "/api/auth",
		Middleware: []Middleware{{
			Path: "/**",
			Handler: func(_ *Context, next Next) (contract.Response, error) {
				middlewareCalls++
				return next()
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("GET", "/outside", contract.RequestOptions{}))
	apiError, ok := contract.AsAPIError(dispatchErr)
	if !ok || apiError.Status != contract.StatusNotFound || response.Status() != contract.StatusNotFound {
		t.Fatalf("unclaimed outside response = %d, %T %v", response.Status(), dispatchErr, dispatchErr)
	}
	if onRequestCalls != 1 || middlewareCalls != 0 || endpointCalls != 0 {
		t.Fatalf(
			"unclaimed outside calls = onRequest %d middleware %d endpoint %d",
			onRequestCalls,
			middlewareCalls,
			endpointCalls,
		)
	}
}

func TestOutsideBasePathRequestRewriteCanRouteInsideBasePath(t *testing.T) {
	plugin := Plugin{
		ID: "outside-to-inside",
		OnRequest: func(ctx *Context) (OnRequestResult, error) {
			if ctx.RoutePath() != "/outside" {
				t.Fatalf("initial outside RoutePath = %q", ctx.RoutePath())
			}
			request := ctx.Request().WithTarget("/api/auth/target", "")
			return OnRequestResult{Request: &request}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "target", Path: "/target", Methods: []string{"GET"},
		Handler: func(ctx *Context) (contract.Response, error) {
			if ctx.RoutePath() != "/target" || ctx.Request().RawPath() != "/api/auth/target" {
				t.Fatalf("rewritten request paths = route %q raw %q", ctx.RoutePath(), ctx.Request().RawPath())
			}
			return contract.TextResponse(contract.StatusOK, "target"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{BasePath: "/api/auth"})
	if err != nil {
		t.Fatal(err)
	}

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("GET", "/outside", contract.RequestOptions{}))
	if dispatchErr != nil || response.Status() != contract.StatusOK || string(response.Body()) != "target" {
		t.Fatalf("outside-to-inside response = %d %q, %v", response.Status(), response.Body(), dispatchErr)
	}
}

func TestInsideBasePathRequestRewriteOutsideEndsNotFound(t *testing.T) {
	var middlewareCalls, endpointCalls int
	plugin := Plugin{
		ID: "inside-to-outside",
		OnRequest: func(ctx *Context) (OnRequestResult, error) {
			if ctx.RoutePath() != "/target" {
				t.Fatalf("initial inside RoutePath = %q", ctx.RoutePath())
			}
			request := ctx.Request().WithTarget("/outside", "")
			return OnRequestResult{Request: &request}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "target", Path: "/target", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			endpointCalls++
			return contract.TextResponse(contract.StatusOK, "target"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{
		BasePath: "/api/auth",
		Middleware: []Middleware{{
			Path: "/**",
			Handler: func(_ *Context, next Next) (contract.Response, error) {
				middlewareCalls++
				return next()
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("GET", "/api/auth/target", contract.RequestOptions{}))
	apiError, ok := contract.AsAPIError(dispatchErr)
	if !ok || apiError.Status != contract.StatusNotFound || response.Status() != contract.StatusNotFound {
		t.Fatalf("inside-to-outside response = %d, %T %v", response.Status(), dispatchErr, dispatchErr)
	}
	if middlewareCalls != 0 || endpointCalls != 0 {
		t.Fatalf("inside-to-outside calls = middleware %d endpoint %d", middlewareCalls, endpointCalls)
	}
}

func TestCanonicalDisabledPathWithBasePathSkipsPluginOnRequest(t *testing.T) {
	var onRequestCalls, middlewareCalls, endpointCalls int
	plugin := Plugin{
		ID: "disabled-with-base-path",
		OnRequest: func(*Context) (OnRequestResult, error) {
			onRequestCalls++
			return OnRequestResult{}, nil
		},
	}
	registry, err := NewRegistry([]Endpoint{{
		Name: "disabled", Path: "/disabled", Methods: []string{"GET"},
		Handler: func(*Context) (contract.Response, error) {
			endpointCalls++
			return contract.TextResponse(contract.StatusOK, "disabled"), nil
		},
	}}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{
		BasePath:      "/api/auth",
		DisabledPaths: []string{"/disabled"},
		Middleware: []Middleware{{
			Path: "/**",
			Handler: func(_ *Context, next Next) (contract.Response, error) {
				middlewareCalls++
				return next()
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("GET", "/api/auth/disabled", contract.RequestOptions{}))
	apiError, ok := contract.AsAPIError(dispatchErr)
	if !ok || apiError.Status != contract.StatusNotFound || response.Status() != contract.StatusNotFound {
		t.Fatalf("disabled response = %d, %T %v", response.Status(), dispatchErr, dispatchErr)
	}
	if onRequestCalls != 0 || middlewareCalls != 0 || endpointCalls != 0 {
		t.Fatalf(
			"disabled calls = onRequest %d middleware %d endpoint %d",
			onRequestCalls,
			middlewareCalls,
			endpointCalls,
		)
	}
}

func TestDispatcherPreservesOptInAPIErrorWireBodyForHTTPAndDirectCalls(t *testing.T) {
	endpoint := Endpoint{
		Name: "oauthError", Path: "/oauth-error", Methods: []string{"POST"},
		Handler: func(*Context) (contract.Response, error) {
			err := contract.NewAPIError(
				contract.StatusBadRequest, "INVALID_GRANT", "Invalid device code",
			).WithWireBody(struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}{Error: "invalid_grant", ErrorDescription: "Invalid device code"})
			return contract.Response{}, err
		},
	}
	registry, err := NewRegistry([]Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"error":"invalid_grant","error_description":"Invalid device code"}`

	response, dispatchErr := dispatcher.Dispatch(contract.NewRequest("POST", "/oauth-error", contract.RequestOptions{}))
	apiError, ok := contract.AsAPIError(dispatchErr)
	if !ok || apiError.Code != "INVALID_GRANT" || apiError.Message != "Invalid device code" {
		t.Fatalf("HTTP error = %T %#v", dispatchErr, dispatchErr)
	}
	if response.Status() != contract.StatusBadRequest || string(response.Body()) != want {
		t.Fatalf("HTTP response = %d %q", response.Status(), response.Body())
	}

	response, dispatchErr = dispatcher.Invoke("oauthError", DirectInput{})
	apiError, ok = contract.AsAPIError(dispatchErr)
	if !ok || apiError.Code != "INVALID_GRANT" || apiError.Message != "Invalid device code" {
		t.Fatalf("direct error = %T %#v", dispatchErr, dispatchErr)
	}
	if response.Status() != contract.StatusBadRequest || string(response.Body()) != want {
		t.Fatalf("direct response = %d %q", response.Status(), response.Body())
	}
}
