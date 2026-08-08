package fiber_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	fiberframework "github.com/gofiber/fiber/v3"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	transport "github.com/pers0na2dev/single-auth/transport/fiber"
	"github.com/pers0na2dev/single-auth/transport/internal/testsuite"
)

const contextHeader = "X-Single-Auth-Conformance-Context"

func TestConformance(t *testing.T) {
	testsuite.Run(t, func(t *testing.T, dispatcher *engine.Dispatcher) testsuite.Exchange {
		t.Helper()
		app, contexts, sequence := testApp(dispatcher)
		return func(input testsuite.Request) (testsuite.Response, error) {
			requestID := strconv.FormatUint(sequence.Add(1), 10)
			requestContext := input.Context
			if requestContext == nil {
				requestContext = context.Background()
			}
			contexts.Store(requestID, requestContext)
			defer contexts.Delete(requestID)

			request, err := http.NewRequest(
				input.Method,
				"http://"+input.Host+input.Target,
				bytes.NewReader(input.Body),
			)
			if err != nil {
				return testsuite.Response{}, err
			}
			request.Host = input.Host
			request.Header.Set(contextHeader, requestID)
			for _, field := range input.Headers.Fields() {
				request.Header.Add(field.Name, field.Value)
			}

			response, err := app.Test(request, fiberframework.TestConfig{Timeout: 0})
			if err != nil {
				return testsuite.Response{}, err
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				return testsuite.Response{}, err
			}
			return testsuite.Response{
				Status:  response.StatusCode,
				Headers: httpHeaders(response.Header),
				Body:    body,
			}, nil
		}
	})
}

func TestMaxBodyBytes(t *testing.T) {
	app := fiberframework.New()
	app.Use(transport.NewHandler(nil, transport.WithMaxBodyBytes(3)))
	request, err := http.NewRequest(http.MethodPost, "http://auth.test/", bytes.NewBufferString("four"))
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
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusRequestEntityTooLarge)
	}
	want := `{"code":"PAYLOAD_TOO_LARGE","message":"Request body is too large"}`
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

func testApp(
	dispatcher *engine.Dispatcher,
) (*fiberframework.App, *sync.Map, *atomic.Uint64) {
	contexts := &sync.Map{}
	sequence := &atomic.Uint64{}
	app := fiberframework.New()
	app.Use(func(ctx fiberframework.Ctx) error {
		requestID := string(ctx.RequestCtx().Request.Header.Peek(contextHeader))
		if requestContext, ok := contexts.Load(requestID); ok {
			ctx.SetContext(requestContext.(context.Context))
		}
		return ctx.Next()
	})
	app.Use(transport.NewHandler(dispatcher))
	return app, contexts, sequence
}

func httpHeaders(source http.Header) contract.Headers {
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	headers := contract.Headers{}
	for _, name := range names {
		for _, value := range source[name] {
			headers.Add(name, value)
		}
	}
	return headers
}
