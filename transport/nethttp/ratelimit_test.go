package nethttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
	transport "github.com/pers0na2dev/single-auth/transport/nethttp"
)

func enabledRateLimiter(maximum int64) *ratelimit.Limiter {
	enabled := true
	now := time.Unix(1_700_000_000, 0)
	return ratelimit.New(ratelimit.Config{
		Enabled:     &enabled,
		Production:  true,
		DefaultRule: ratelimit.Rule{Window: 10, Max: maximum},
		Now:         func() time.Time { return now },
	}, ratelimit.NewMemoryStore(ratelimit.MemoryOptions{Now: func() time.Time { return now }}))
}

func rateLimitRequest(target string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	return request
}

func TestCheckRateLimitAdaptsNetHTTPRequest(t *testing.T) {
	limiter := enabledRateLimiter(2)
	request := rateLimitRequest("https://example.com/get-session?nonce=one")
	result, err := transport.CheckRateLimit(nil, limiter, request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Allowed || result.Path != "/get-session" || result.Key != "198.51.100.10|/get-session" {
		t.Fatalf("result = %#v", result)
	}

	_, err = transport.CheckRateLimit(t.Context(), limiter, nil)
	if !errors.Is(err, ratelimit.ErrNilRequest) {
		t.Fatalf("nil request error = %v", err)
	}
}

func TestWriteRateLimitUsesStableWireResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	transport.WriteRateLimit(recorder, 7)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("X-Retry-After"); got != "7" {
		t.Fatalf("retry header = %q", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/plain;charset=UTF-8" {
		t.Fatalf("content type = %q", got)
	}
	if got := recorder.Body.String(); got != ratelimit.TooManyRequestsBody {
		t.Fatalf("body = %q", got)
	}
}

func TestRateLimitMiddlewareStopsBlockedRequest(t *testing.T) {
	limiter := enabledRateLimiter(1)
	nextCalls := 0
	handler := transport.RateLimitMiddleware(
		limiter,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalls++ }),
		nil,
	)

	for index := 0; index < 2; index++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, rateLimitRequest("https://example.com/get-session"))
		want := http.StatusOK
		if index == 1 {
			want = http.StatusTooManyRequests
		}
		if recorder.Code != want {
			t.Fatalf("request %d status = %d, want %d", index, recorder.Code, want)
		}
	}
	if nextCalls != 1 {
		t.Fatalf("next calls = %d", nextCalls)
	}
}
