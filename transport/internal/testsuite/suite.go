// Package testsuite contains the transport-neutral adapter conformance suite.
// It is internal to the transport tree and shared by the net/http, fasthttp,
// and Fiber adapter tests so every transport proves the same behavior.
package testsuite

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

// Request is one transport-independent conformance exchange.
type Request struct {
	Context context.Context
	Method  string
	Target  string
	Host    string
	Headers contract.Headers
	Body    []byte
}

// Response is the transport-observable result of one exchange.
type Response struct {
	Status  int
	Headers contract.Headers
	Body    []byte
}

// Exchange sends one request through a concrete server adapter.
type Exchange func(Request) (Response, error)

// Factory attaches a concrete transport to dispatcher.
type Factory func(*testing.T, *engine.Dispatcher) Exchange

type fixtureState struct {
	cancelStarted     chan struct{}
	cancelStartedOnce sync.Once

	retainedMu  sync.Mutex
	retained    contract.Request
	hasRetained bool
}

// Run executes the same status, body, URL, header, cancellation, route
// visibility, and reusable-buffer checks against a transport adapter.
func Run(t *testing.T, factory Factory) {
	t.Helper()
	dispatcher, state := newDispatcher(t)
	exchange := factory(t, dispatcher)
	if exchange == nil {
		t.Fatal("transport factory returned a nil exchange")
	}

	t.Run("request and response fidelity", func(t *testing.T) {
		response, err := exchange(Request{
			Context: context.Background(),
			Method:  "POST",
			Target:  "/api/auth/echo/segment%2Fvalue?tag=first&tag=second&raw=a%2Bb",
			Host:    "auth.test",
			Headers: contract.NewHeaders(
				contract.HeaderField{Name: "X-Input", Value: "first"},
				contract.HeaderField{Name: "X-Input", Value: "second"},
				contract.HeaderField{Name: "Content-Type", Value: "application/octet-stream"},
			),
			Body: []byte("payload\x00bytes"),
		})
		if err != nil {
			t.Fatalf("exchange failed: %v", err)
		}
		if response.Status != 207 {
			t.Fatalf("status = %d, want 207; body=%s", response.Status, response.Body)
		}
		wantBody := "{\"pathParam\":\"segment/value\",\"tags\":[\"first\",\"second\"],\"raw\":\"a+b\",\"headers\":[\"first\",\"second\"],\"body\":\"payload\\u0000bytes\"}"
		if string(response.Body) != wantBody {
			t.Fatalf("body = %q, want %q", response.Body, wantBody)
		}
		assertValues(t, response.Headers, "Content-Type", []string{"application/json; charset=utf-8"})
		assertValues(t, response.Headers, "X-Multi", []string{"first", "second"})
		assertValues(t, response.Headers, "Set-Cookie", []string{
			"session=alpha; Path=/; HttpOnly; SameSite=Lax",
			"csrf=beta; Path=/api/auth; Secure; SameSite=None",
		})
	})

	t.Run("server-only endpoint is hidden from HTTP", func(t *testing.T) {
		response, err := exchange(Request{
			Context: context.Background(),
			Method:  "GET",
			Target:  "/api/auth/private",
			Host:    "auth.test",
		})
		if err != nil {
			t.Fatalf("exchange failed: %v", err)
		}
		if response.Status != contract.StatusNotFound {
			t.Fatalf("status = %d, want %d", response.Status, contract.StatusNotFound)
		}
		wantBody := `{"code":"NOT_FOUND","message":"Not Found"}`
		if string(response.Body) != wantBody {
			t.Fatalf("body = %q, want %q", response.Body, wantBody)
		}

		directResponse, directErr := dispatcher.Invoke("private", engine.DirectInput{
			Request: contract.NewRequest("GET", "/private", contract.RequestOptions{}),
		})
		if directErr != nil {
			t.Fatalf("direct server-only invocation failed: %v", directErr)
		}
		if directResponse.Status() != contract.StatusOK || string(directResponse.Body()) != "private" {
			t.Fatalf(
				"direct response = (%d, %q), want (200, private)",
				directResponse.Status(),
				directResponse.Body(),
			)
		}
	})

	t.Run("request cancellation reaches dispatcher", func(t *testing.T) {
		requestContext, cancel := context.WithCancel(context.Background())
		defer cancel()

		type exchangeResult struct {
			response Response
			err      error
		}
		result := make(chan exchangeResult, 1)
		go func() {
			response, err := exchange(Request{
				Context: requestContext,
				Method:  "GET",
				Target:  "/api/auth/cancel",
				Host:    "auth.test",
			})
			result <- exchangeResult{response: response, err: err}
		}()

		select {
		case <-state.cancelStarted:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not enter cancellation endpoint")
		}
		cancel()

		var completed exchangeResult
		select {
		case completed = <-result:
		case <-time.After(2 * time.Second):
			t.Fatal("transport did not propagate request cancellation")
		}
		if completed.err != nil {
			t.Fatalf("exchange failed: %v", completed.err)
		}
		if completed.response.Status != contract.StatusOK {
			t.Fatalf(
				"status = %d, want %d",
				completed.response.Status,
				contract.StatusOK,
			)
		}
		if string(completed.response.Body) != "context cancelled" {
			t.Fatalf(
				"body = %q, want context cancelled",
				completed.response.Body,
			)
		}
	})

	t.Run("transport buffers do not escape handler lifetime", func(t *testing.T) {
		firstBody := []byte("first-body")
		_, err := exchange(Request{
			Context: context.Background(),
			Method:  "POST",
			Target:  "/api/auth/retain",
			Host:    "auth.test",
			Headers: contract.NewHeaders(contract.HeaderField{
				Name:  "X-Retain",
				Value: "first-header",
			}),
			Body: firstBody,
		})
		if err != nil {
			t.Fatalf("first exchange failed: %v", err)
		}
		for index := range firstBody {
			firstBody[index] = 'x'
		}

		_, err = exchange(Request{
			Context: context.Background(),
			Method:  "POST",
			Target:  "/api/auth/retain",
			Host:    "auth.test",
			Headers: contract.NewHeaders(contract.HeaderField{
				Name:  "X-Retain",
				Value: "second-header",
			}),
			Body: []byte("second-body"),
		})
		if err != nil {
			t.Fatalf("second exchange failed: %v", err)
		}

		retained, ok := state.retainedRequest()
		if !ok {
			t.Fatal("endpoint did not retain its first request snapshot")
		}
		if string(retained.Body()) != "first-body" {
			t.Fatalf("retained body = %q, want first-body", retained.Body())
		}
		assertValues(t, retained.Headers(), "X-Retain", []string{"first-header"})
	})
}

func newDispatcher(t *testing.T) (*engine.Dispatcher, *fixtureState) {
	t.Helper()
	state := &fixtureState{cancelStarted: make(chan struct{})}
	registry, err := engine.NewRegistry([]engine.Endpoint{
		{
			Name:    "echo",
			Path:    "/echo/:value",
			Methods: []string{"POST"},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				request := ctx.Request()
				query, queryErr := request.Query()
				if queryErr != nil {
					return contract.Response{}, queryErr
				}
				pathParam, ok := ctx.Param("value")
				if !ok {
					return contract.Response{}, fmt.Errorf("missing path parameter")
				}
				payload := struct {
					PathParam string   `json:"pathParam"`
					Tags      []string `json:"tags"`
					Raw       string   `json:"raw"`
					Headers   []string `json:"headers"`
					Body      string   `json:"body"`
				}{
					PathParam: pathParam,
					Tags:      query["tag"],
					Raw:       query.Get("raw"),
					Headers:   request.Headers().Values("X-Input"),
					Body:      string(request.Body()),
				}
				response, responseErr := contract.JSONResponse(207, payload)
				if responseErr != nil {
					return contract.Response{}, responseErr
				}
				return response.
					WithAddedHeader("X-Multi", "first").
					WithAddedHeader("X-Multi", "second").
					WithAddedHeader("Set-Cookie", "session=alpha; Path=/; HttpOnly; SameSite=Lax").
					WithAddedHeader("Set-Cookie", "csrf=beta; Path=/api/auth; Secure; SameSite=None"), nil
			},
		},
		{
			Name:       "private",
			Path:       "/private",
			Methods:    []string{"GET"},
			ServerOnly: true,
			Handler: func(*engine.Context) (contract.Response, error) {
				return contract.TextResponse(contract.StatusOK, "private"), nil
			},
		},
		{
			Name:    "cancel",
			Path:    "/cancel",
			Methods: []string{"GET"},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				state.cancelStartedOnce.Do(func() {
					close(state.cancelStarted)
				})
				select {
				case <-ctx.GoContext().Done():
					return contract.TextResponse(contract.StatusOK, "context cancelled"), nil
				case <-time.After(5 * time.Second):
					return contract.TextResponse(
						contract.StatusInternalServerError,
						"context was not cancelled",
					), nil
				}
			},
		},
		{
			Name:    "retain",
			Path:    "/retain",
			Methods: []string{"POST"},
			Handler: func(ctx *engine.Context) (contract.Response, error) {
				state.retainFirst(ctx.Request())
				return contract.NewResponse(204, contract.Headers{}, nil), nil
			},
		},
	})
	if err != nil {
		t.Fatalf("build conformance registry: %v", err)
	}
	dispatcher, err := engine.NewDispatcher(registry, engine.DispatcherOptions{
		BasePath: "/api/auth",
	})
	if err != nil {
		t.Fatalf("build conformance dispatcher: %v", err)
	}
	return dispatcher, state
}

func (state *fixtureState) retainFirst(request contract.Request) {
	state.retainedMu.Lock()
	defer state.retainedMu.Unlock()
	if state.hasRetained {
		return
	}
	state.retained = request.Clone()
	state.hasRetained = true
}

func (state *fixtureState) retainedRequest() (contract.Request, bool) {
	state.retainedMu.Lock()
	defer state.retainedMu.Unlock()
	if !state.hasRetained {
		return contract.Request{}, false
	}
	return state.retained.Clone(), true
}

func assertValues(t *testing.T, headers contract.Headers, name string, want []string) {
	t.Helper()
	got := headers.Values(name)
	if !slices.Equal(got, want) {
		t.Fatalf("%s values = %#v, want %#v", name, got, want)
	}
}
