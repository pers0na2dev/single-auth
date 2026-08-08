package nethttp_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
	"github.com/pers0na2dev/single-auth/transport/internal/testsuite"
	transport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func TestConformance(t *testing.T) {
	testsuite.Run(t, func(t *testing.T, dispatcher *engine.Dispatcher) testsuite.Exchange {
		t.Helper()
		handler := transport.NewHandler(dispatcher)
		return func(input testsuite.Request) (testsuite.Response, error) {
			ctx := input.Context
			if ctx == nil {
				ctx = context.Background()
			}
			request, err := http.NewRequestWithContext(
				ctx,
				input.Method,
				"http://"+input.Host+input.Target,
				bytes.NewReader(input.Body),
			)
			if err != nil {
				return testsuite.Response{}, err
			}
			request.Host = input.Host
			for _, field := range input.Headers.Fields() {
				request.Header.Add(field.Name, field.Value)
			}

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			result := recorder.Result()
			defer result.Body.Close()
			body, err := io.ReadAll(result.Body)
			if err != nil {
				return testsuite.Response{}, err
			}
			return testsuite.Response{
				Status:  result.StatusCode,
				Headers: httpHeaders(result.Header),
				Body:    body,
			}, nil
		}
	})
}

func TestMaxBodyBytes(t *testing.T) {
	handler := transport.NewHandler(nil, transport.WithMaxBodyBytes(3))
	request := httptest.NewRequest(http.MethodPost, "http://auth.test/", bytes.NewReader([]byte("four")))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
	want := `{"code":"PAYLOAD_TOO_LARGE","message":"Request body is too large"}`
	if recorder.Body.String() != want {
		t.Fatalf("body = %q, want %q", recorder.Body.String(), want)
	}
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
