package bearer

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/pers0na2dev/single-auth/core/contract"
	"github.com/pers0na2dev/single-auth/core/engine"
)

func staticEndpoint(
	name, path string,
	handler engine.HandlerFunc,
) engine.Endpoint {
	return engine.Endpoint{Name: name, Path: path, Methods: []string{"GET"}, Handler: handler}
}

func TestSessionSetCookieIsExposedAsBearerToken(t *testing.T) {
	values := loadBearerTestValues(t)
	endpoint := staticEndpoint("issue", "/issue", func(*engine.Context) (contract.Response, error) {
		headers := contract.NewHeaders(
			contract.HeaderField{
				Name:  "Set-Cookie",
				Value: values.SessionCookieName + "=" + values.EncodedSignedToken + "; Max-Age=604800; Path=/; HttpOnly; SameSite=Lax",
			},
			contract.HeaderField{Name: "Access-Control-Expose-Headers", Value: "x-request-id"},
		)
		return contract.NewResponse(contract.StatusOK, headers, []byte("ok")), nil
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	token, ok := response.Headers().Get("set-auth-token")
	if !ok || token != values.SignedToken {
		t.Fatalf("set-auth-token = %q, %v", token, ok)
	}
	exposed, _ := response.Headers().Get("Access-Control-Expose-Headers")
	if exposed != values.ExposedHeaders {
		t.Fatalf("exposed headers = %q", exposed)
	}
	if len(response.Headers().Values("Set-Cookie")) != 1 || string(response.Body()) != "ok" {
		t.Fatalf("response changed = %#v %q", response.Headers().Fields(), response.Body())
	}
}

func TestResponseExposureMergesHeadersWithJavaScriptSetSemantics(t *testing.T) {
	values := loadBearerTestValues(t)
	endpoint := staticEndpoint("issue", "/issue", func(*engine.Context) (contract.Response, error) {
		headers := contract.NewHeaders(
			contract.HeaderField{Name: "Set-Cookie", Value: values.SessionCookieName + "=" + values.EncodedSignedToken},
			contract.HeaderField{
				Name:  "Access-Control-Expose-Headers",
				Value: " x-request-id, Set-Auth-Token, x-request-id,  ",
			},
			contract.HeaderField{Name: "Access-Control-Expose-Headers", Value: "x-trace-id"},
			contract.HeaderField{Name: "set-auth-token", Value: "stale"},
		)
		return contract.NewResponse(201, headers, []byte("created")), nil
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status() != 201 || string(response.Body()) != "created" {
		t.Fatalf("response status/body = %d %q", response.Status(), response.Body())
	}
	if token, _ := response.Headers().Get("set-auth-token"); token != values.SignedToken {
		t.Fatalf("token = %q", token)
	}
	exposed, _ := response.Headers().Get("Access-Control-Expose-Headers")
	if exposed != "x-request-id, Set-Auth-Token, x-trace-id, set-auth-token" {
		t.Fatalf("exposed = %q", exposed)
	}
}

func TestResponseDoesNotExposeAbsentOrDeletedSessionCookie(t *testing.T) {
	values := loadBearerTestValues(t)
	tests := []struct {
		name       string
		setCookies []string
	}{
		{name: "none"},
		{name: "different cookie", setCookies: []string{"theme=dark; Path=/"}},
		{name: "empty value", setCookies: []string{values.SessionCookieName + "=; Path=/"}},
		{name: "max age zero", setCookies: []string{values.SessionCookieName + "=" + values.EncodedSignedToken + "; Max-Age=0"}},
		{name: "last duplicate deletes", setCookies: []string{
			values.SessionCookieName + "=" + values.EncodedSignedToken + "; Max-Age=100",
			values.SessionCookieName + "=; Max-Age=0",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint := staticEndpoint("issue", "/issue", func(*engine.Context) (contract.Response, error) {
				headers := contract.Headers{}
				for _, value := range test.setCookies {
					headers.Add("Set-Cookie", value)
				}
				return contract.NewResponse(contract.StatusOK, headers, nil), nil
			})
			dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
				Secret: values.Secret, SessionCookieName: values.SessionCookieName,
			}}, endpoint)
			response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
			if err != nil {
				t.Fatal(err)
			}
			if response.Headers().Has("set-auth-token") || response.Headers().Has("Access-Control-Expose-Headers") {
				t.Fatalf("deleted token exposed: %#v", response.Headers().Fields())
			}
		})
	}
}

func TestResponseUsesLastSessionCookieAndOnlyZeroMeansDeletion(t *testing.T) {
	values := loadBearerTestValues(t)
	secondToken := signCookieValue("second-token", values.Secret)
	endpoint := staticEndpoint("issue", "/issue", func(*engine.Context) (contract.Response, error) {
		headers := contract.NewHeaders(
			contract.HeaderField{Name: "Set-Cookie", Value: values.SessionCookieName + "=; Max-Age=0"},
			contract.HeaderField{Name: "Set-Cookie", Value: values.SessionCookieName + "=" + secondToken + "; Max-Age=-1"},
		)
		return contract.NewResponse(contract.StatusOK, headers, nil), nil
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	if token, _ := response.Headers().Get("set-auth-token"); token != secondToken {
		t.Fatalf("last session cookie token = %q", token)
	}
}

func TestCommaJoinedSetCookieWithExpiresIsParsed(t *testing.T) {
	values := loadBearerTestValues(t)
	joined := "theme=dark; Expires=Wed, 21 Oct 2026 07:28:00 GMT, " +
		values.SessionCookieName + "=" + values.EncodedSignedToken + "; Path=/"
	endpoint := staticEndpoint("issue", "/issue", func(*engine.Context) (contract.Response, error) {
		return contract.NewResponse(contract.StatusOK, contract.NewHeaders(
			contract.HeaderField{Name: "Set-Cookie", Value: joined},
		), nil), nil
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	if err != nil {
		t.Fatal(err)
	}
	if token, _ := response.Headers().Get("set-auth-token"); token != values.SignedToken {
		t.Fatalf("joined Set-Cookie token = %q", token)
	}
}

func TestAfterHookRunsForTypedEndpointErrors(t *testing.T) {
	values := loadBearerTestValues(t)
	endpoint := staticEndpoint("issue", "/issue", func(ctx *engine.Context) (contract.Response, error) {
		ctx.AddSetCookie(values.SessionCookieName + "=" + values.EncodedSignedToken + "; Path=/")
		return contract.Response{}, contract.NewAPIError(contract.StatusUnauthorized, "DENIED", "Denied")
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	apiError, ok := contract.AsAPIError(err)
	if !ok || apiError.Code != "DENIED" || response.Status() != contract.StatusUnauthorized {
		t.Fatalf("typed response = %d %#v err=%v", response.Status(), response.Headers().Fields(), err)
	}
	if token, _ := response.Headers().Get("set-auth-token"); token != values.SignedToken {
		t.Fatalf("typed error did not expose token: %q", token)
	}
}

func TestUnknownEndpointErrorsSkipAfterHook(t *testing.T) {
	values := loadBearerTestValues(t)
	endpoint := staticEndpoint("issue", "/issue", func(ctx *engine.Context) (contract.Response, error) {
		ctx.AddSetCookie(values.SessionCookieName + "=" + values.EncodedSignedToken)
		return contract.Response{}, errors.New("boom")
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)
	response, err := dispatch(t, dispatcher, "GET", "/issue", contract.Headers{})
	if err == nil || response.Headers().Has("set-auth-token") {
		t.Fatalf("unknown error response = %#v err=%v", response.Headers().Fields(), err)
	}
}

func TestBearerAfterHookIsRaceSafe(t *testing.T) {
	values := loadBearerTestValues(t)
	endpoint := staticEndpoint("issue", "/issue", func(ctx *engine.Context) (contract.Response, error) {
		value, _ := ctx.Request().Headers().Get("X-Token")
		return contract.NewResponse(contract.StatusOK, contract.NewHeaders(
			contract.HeaderField{Name: "Set-Cookie", Value: values.SessionCookieName + "=" + signCookieValue(value, values.Secret)},
		), nil), nil
	})
	dispatcher, _ := newTestDispatcher(t, Options{Runtime: Runtime{
		Secret: values.Secret, SessionCookieName: values.SessionCookieName,
	}}, endpoint)

	const requests = 64
	errorsByRequest := make([]error, requests)
	var group sync.WaitGroup
	group.Add(requests)
	for index := range requests {
		go func() {
			defer group.Done()
			value := fmt.Sprintf("token-%d", index)
			request := contract.NewRequest("GET", "/api/auth/issue", contract.RequestOptions{
				Headers: contract.NewHeaders(contract.HeaderField{Name: "X-Token", Value: value}),
			})
			response, err := dispatcher.Dispatch(request)
			if err == nil {
				want := signCookieValue(value, values.Secret)
				if got, _ := response.Headers().Get("set-auth-token"); got != want {
					err = fmt.Errorf("token = %q, want %q", got, want)
				}
			}
			errorsByRequest[index] = err
		}()
	}
	group.Wait()
	for index, err := range errorsByRequest {
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
	}
}
