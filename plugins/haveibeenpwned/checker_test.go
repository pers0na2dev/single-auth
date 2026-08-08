package haveibeenpwned

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
)

func TestCheckPasswordEmptySkipsTransport(t *testing.T) {
	called := false
	err := CheckPassword(nil, "", Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, errors.New("must not be called")
	})})
	if err != nil || called {
		t.Fatalf("empty password: called=%v err=%v", called, err)
	}
}

func TestCheckPasswordMatchesSuffixWithoutCount(t *testing.T) {
	password := "suffix-only-password"
	err := CheckPassword(t.Context(), password, Options{
		CustomPasswordCompromisedMessage: "compromised",
		HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
			return response(http.StatusOK, "DEADBEEF:10\n"+strings.ToLower(passwordSuffix(password))+"\n"), nil
		}),
	})
	assertAPIError(t, err, contract.StatusBadRequest, ErrorPasswordCompromised, "compromised")
}

func TestCheckPasswordDoesNotTrimRangeSuffix(t *testing.T) {
	password := "space-sensitive-password"
	err := CheckPassword(t.Context(), password, Options{HTTPClient: doerFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, " "+passwordSuffix(password)+":1\n"), nil
	})})
	if err != nil {
		t.Fatalf("space-prefixed suffix matched unexpectedly: %v", err)
	}
}

func TestCheckPasswordStatusAndTransportFailures(t *testing.T) {
	tests := []struct {
		name    string
		doer    HTTPDoer
		message string
		cause   bool
	}{
		{
			name: "redirect-status",
			doer: doerFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusMultipleChoices, ""), nil
			}),
			message: "Failed to check password. Status: 300",
		},
		{
			name: "transport",
			doer: doerFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("offline")
			}),
			message: "Failed to check password. Please try again later.", cause: true,
		},
		{
			name:    "nil-response",
			doer:    doerFunc(func(*http.Request) (*http.Response, error) { return nil, nil }),
			message: "Failed to check password. Please try again later.", cause: true,
		},
		{
			name: "nil-body",
			doer: doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK}, nil
			}),
			message: "Failed to check password. Please try again later.", cause: true,
		},
		{
			name: "read-body",
			doer: doerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: failingBody{}}, nil
			}),
			message: "Failed to check password. Please try again later.", cause: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CheckPassword(t.Context(), "failure-password", Options{HTTPClient: test.doer})
			apiError := assertAPIError(t, err, contract.StatusInternalServerError, "INTERNAL_SERVER_ERROR", test.message)
			if (apiError.Cause != nil) != test.cause {
				t.Errorf("cause = %#v, expected presence %v", apiError.Cause, test.cause)
			}
		})
	}
}

func TestCheckPasswordCarriesCallerContext(t *testing.T) {
	type contextKey string
	const key contextKey = "range-request"
	ctx := context.WithValue(t.Context(), key, "expected")
	err := CheckPassword(ctx, "context-password", Options{HTTPClient: doerFunc(func(request *http.Request) (*http.Response, error) {
		if actual := request.Context().Value(key); actual != "expected" {
			t.Fatalf("request context value = %#v", actual)
		}
		return response(http.StatusOK, ""), nil
	})})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDefaultPathsReturnsIndependentCopies(t *testing.T) {
	first := DefaultPaths()
	second := DefaultPaths()
	first[0] = "/mutated"
	if second[0] != "/sign-up/email" || defaultPaths[0] != "/sign-up/email" {
		t.Fatalf("default paths were mutated: second=%#v defaults=%#v", second, defaultPaths)
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failure") }
func (failingBody) Close() error             { return nil }

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func assertAPIError(
	t *testing.T,
	err error,
	status int,
	code string,
	message string,
) *contract.APIError {
	t.Helper()
	apiError, ok := contract.AsAPIError(err)
	if !ok {
		t.Fatalf("error = %#v, want API error", err)
	}
	if apiError.Status != status || apiError.Code != code || apiError.Message != message {
		t.Fatalf("error = %#v, want status=%d code=%q message=%q", apiError, status, code, message)
	}
	return apiError
}
