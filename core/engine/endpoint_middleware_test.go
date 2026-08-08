package engine

import (
	"errors"
	"reflect"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestEndpointUseSequentialContextMergeAcrossDispatchModes(t *testing.T) {
	for _, mode := range []string{"http", "direct", "isolated"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			events := make([]string, 0, 7)
			afterSawContext := false
			endpoint := Endpoint{
				Name: "probe", Path: "/probe", Methods: []string{"GET"},
				Use: []EndpointMiddlewareFunc{
					func(ctx *Context) (EndpointMiddlewareResult, error) {
						events = append(events, "use-one")
						if _, exists := ctx.Value("one"); exists {
							t.Fatal("first middleware observed a future context value")
						}
						return EndpointMiddlewareResult{Values: map[string]any{
							"one": 1, "shared": "first",
						}}, nil
					},
					func(ctx *Context) (EndpointMiddlewareResult, error) {
						events = append(events, "use-two")
						one, oneOK := ctx.Value("one")
						shared, sharedOK := ctx.Value("shared")
						if !oneOK || one != 1 || !sharedOK || shared != "first" {
							t.Fatalf("second middleware context one=%#v shared=%#v", one, shared)
						}
						return EndpointMiddlewareResult{Values: map[string]any{
							"two": 2, "shared": "second",
						}}, nil
					},
				},
				Handler: func(ctx *Context) (contract.Response, error) {
					events = append(events, "handler")
					one, oneOK := ctx.Value("one")
					two, twoOK := ctx.Value("two")
					shared, sharedOK := ctx.Value("shared")
					if !oneOK || one != 1 || !twoOK || two != 2 || !sharedOK || shared != "second" {
						t.Fatalf("handler context one=%#v two=%#v shared=%#v", one, two, shared)
					}
					return contract.JSONResponse(contract.StatusOK, map[string]bool{"ok": true})
				},
			}
			hooks := Hooks{After: []AfterHook{{
				Name: "observe",
				Handler: func(ctx *Context, response contract.Response) (*contract.Response, error) {
					events = append(events, "after")
					shared, ok := ctx.Value("shared")
					returned, _, returnedOK := ctx.Returned()
					afterSawContext = ok && shared == "second" && returnedOK && returned.Status() == contract.StatusOK && response.Status() == contract.StatusOK
					return nil, nil
				},
			}}}
			routerMiddleware := []Middleware{{
				Name: "outer", Path: "/probe",
				Handler: func(_ *Context, next Next) (contract.Response, error) {
					events = append(events, "router-before")
					response, err := next()
					events = append(events, "router-after")
					return response, err
				},
			}}
			response, err := runEndpointUseTestMode(t, mode, endpoint, hooks, routerMiddleware)
			if err != nil || response.Status() != contract.StatusOK {
				t.Fatalf("response status=%d err=%v", response.Status(), err)
			}
			switch mode {
			case "http":
				want := []string{"router-before", "use-one", "use-two", "handler", "after", "router-after"}
				if !reflect.DeepEqual(events, want) || !afterSawContext {
					t.Fatalf("events=%#v afterSawContext=%v, want %#v", events, afterSawContext, want)
				}
			case "direct":
				want := []string{"use-one", "use-two", "handler", "after"}
				if !reflect.DeepEqual(events, want) || !afterSawContext {
					t.Fatalf("events=%#v afterSawContext=%v, want %#v", events, afterSawContext, want)
				}
			case "isolated":
				want := []string{"use-one", "use-two", "handler"}
				if !reflect.DeepEqual(events, want) || afterSawContext {
					t.Fatalf("events=%#v afterSawContext=%v, want %#v", events, afterSawContext, want)
				}
			}
		})
	}
}

func TestEndpointUseShortCircuitAndErrorAcrossDispatchModes(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		middleware EndpointMiddlewareFunc
		wantStatus int
		wantError  bool
	}{
		{
			name: "short-circuit",
			middleware: func(*Context) (EndpointMiddlewareResult, error) {
				response := contract.TextResponse(202, "short")
				return EndpointMiddlewareResult{
					Values: map[string]any{"terminal": "short"}, Response: &response,
				}, nil
			},
			wantStatus: 202,
		},
		{
			name: "typed-error",
			middleware: func(*Context) (EndpointMiddlewareResult, error) {
				return EndpointMiddlewareResult{}, contract.NewAPIError(
					contract.StatusBadRequest, "USE_FAILED", "Use failed",
				)
			},
			wantStatus: contract.StatusBadRequest,
			wantError:  true,
		},
	} {
		scenario := scenario
		t.Run(scenario.name, func(t *testing.T) {
			for _, mode := range []string{"http", "direct", "isolated"} {
				mode := mode
				t.Run(mode, func(t *testing.T) {
					handlerCalled := false
					laterUseCalled := false
					afterCalled := false
					endpoint := Endpoint{
						Name: "probe", Path: "/probe", Methods: []string{"GET"},
						Use: []EndpointMiddlewareFunc{
							func(*Context) (EndpointMiddlewareResult, error) {
								return EndpointMiddlewareResult{Values: map[string]any{"prepared": true}}, nil
							},
							scenario.middleware,
							func(*Context) (EndpointMiddlewareResult, error) {
								laterUseCalled = true
								return EndpointMiddlewareResult{}, nil
							},
						},
						Handler: func(*Context) (contract.Response, error) {
							handlerCalled = true
							return contract.TextResponse(contract.StatusOK, "handler"), nil
						},
					}
					hooks := Hooks{After: []AfterHook{{
						Name: "observe",
						Handler: func(ctx *Context, _ contract.Response) (*contract.Response, error) {
							prepared, ok := ctx.Value("prepared")
							if !ok || prepared != true {
								t.Fatalf("after hook prepared=%#v ok=%v", prepared, ok)
							}
							if scenario.name == "short-circuit" {
								terminal, exists := ctx.Value("terminal")
								if !exists || terminal != "short" {
									t.Fatalf("after hook terminal=%#v exists=%v", terminal, exists)
								}
							}
							afterCalled = true
							return nil, nil
						},
					}}}
					response, err := runEndpointUseTestMode(t, mode, endpoint, hooks, nil)
					if response.Status() != scenario.wantStatus || (err != nil) != scenario.wantError {
						t.Fatalf("status=%d err=%v", response.Status(), err)
					}
					if handlerCalled || laterUseCalled {
						t.Fatalf("handlerCalled=%v laterUseCalled=%v", handlerCalled, laterUseCalled)
					}
					if mode == "isolated" && afterCalled {
						t.Fatal("isolated invocation unexpectedly ran registry after hook")
					}
					if mode != "isolated" && !afterCalled {
						t.Fatal("dispatcher after hook did not observe endpoint middleware outcome")
					}
				})
			}
		})
	}
}

func TestEndpointUseRegistrySnapshotsAndValidatesDeclarations(t *testing.T) {
	originalCalls := 0
	replacementCalls := 0
	original := func(*Context) (EndpointMiddlewareResult, error) {
		originalCalls++
		return EndpointMiddlewareResult{}, nil
	}
	replacement := func(*Context) (EndpointMiddlewareResult, error) {
		replacementCalls++
		return EndpointMiddlewareResult{}, nil
	}
	use := []EndpointMiddlewareFunc{original}
	registry, err := NewRegistry([]Endpoint{{
		Name: "probe", Path: "/probe", Methods: []string{"GET"}, Use: use,
		Handler: func(*Context) (contract.Response, error) {
			return contract.TextResponse(contract.StatusOK, "ok"), nil
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	use[0] = replacement
	returned, ok := registry.Endpoint("probe")
	if !ok {
		t.Fatal("registered endpoint missing")
	}
	returned.Use[0] = replacement
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dispatcher.Invoke("probe", DirectInput{
		Request: contract.NewRequest("GET", "/:direct", contract.RequestOptions{}),
	}); err != nil {
		t.Fatal(err)
	}
	if originalCalls != 1 || replacementCalls != 0 {
		t.Fatalf("originalCalls=%d replacementCalls=%d", originalCalls, replacementCalls)
	}

	_, err = NewRegistry([]Endpoint{{
		Name: "invalid", Path: "/invalid", Methods: []string{"GET"},
		Use: []EndpointMiddlewareFunc{nil},
		Handler: func(*Context) (contract.Response, error) {
			return contract.Response{}, nil
		},
	}})
	var registryError *RegistryError
	if !errors.As(err, &registryError) || registryError.Kind != RegistryErrorInvalidEndpoint || registryError.Message != "endpoint middleware must not be nil" {
		t.Fatalf("nil endpoint middleware error=%#v", err)
	}
}

func TestRunEndpointIsolatedSnapshotsEndpointUseBeforeExecution(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	originalSecondCalled := false
	replacementCalled := false
	endpoint := Endpoint{
		Name: "probe", Path: "/probe", Methods: []string{"GET"},
		Use: []EndpointMiddlewareFunc{
			func(*Context) (EndpointMiddlewareResult, error) {
				close(entered)
				<-release
				return EndpointMiddlewareResult{}, nil
			},
			func(*Context) (EndpointMiddlewareResult, error) {
				originalSecondCalled = true
				return EndpointMiddlewareResult{}, nil
			},
		},
		Handler: func(*Context) (contract.Response, error) {
			return contract.TextResponse(contract.StatusOK, "ok"), nil
		},
	}
	type result struct {
		response contract.Response
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		source := newContext(contract.NewRequest("GET", "/outer", contract.RequestOptions{}), true)
		response, err := RunEndpointIsolated(source, source.Request(), endpoint)
		completed <- result{response: response, err: err}
	}()
	<-entered
	endpoint.Use[1] = func(*Context) (EndpointMiddlewareResult, error) {
		replacementCalled = true
		return EndpointMiddlewareResult{}, nil
	}
	close(release)
	actual := <-completed
	if actual.err != nil || actual.response.Status() != contract.StatusOK {
		t.Fatalf("status=%d err=%v", actual.response.Status(), actual.err)
	}
	if !originalSecondCalled || replacementCalled {
		t.Fatalf("originalSecondCalled=%v replacementCalled=%v", originalSecondCalled, replacementCalled)
	}
}

func runEndpointUseTestMode(
	t *testing.T,
	mode string,
	endpoint Endpoint,
	hooks Hooks,
	middleware []Middleware,
) (contract.Response, error) {
	t.Helper()
	if mode == "isolated" {
		source := newContext(contract.NewRequest("GET", "/outer", contract.RequestOptions{}), true)
		return RunEndpointIsolated(source, source.Request().WithMethod("GET"), endpoint)
	}
	registry, err := NewRegistry([]Endpoint{endpoint})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := NewDispatcher(registry, DispatcherOptions{Hooks: hooks, Middleware: middleware})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "direct" {
		return dispatcher.Invoke(endpoint.Name, DirectInput{
			Request: contract.NewRequest("GET", "/:direct", contract.RequestOptions{}),
		})
	}
	return dispatcher.Dispatch(contract.NewRequest("GET", endpoint.Path, contract.RequestOptions{}))
}
