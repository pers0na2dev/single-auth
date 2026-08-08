package fasthttp_test

import (
	"errors"
	"testing"
	"time"

	fasthttpserver "github.com/valyala/fasthttp"

	"github.com/pers0na2dev/single-auth/security/ratelimit"
	transport "github.com/pers0na2dev/single-auth/transport/fasthttp"
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

func rateLimitContext(target string) *fasthttpserver.RequestCtx {
	var request fasthttpserver.Request
	request.SetRequestURI(target)
	request.Header.Set("X-Forwarded-For", "198.51.100.10")
	ctx := &fasthttpserver.RequestCtx{}
	ctx.Init(&request, nil, nil)
	return ctx
}

func TestCheckRateLimitAdaptsFastHTTPRequest(t *testing.T) {
	limiter := enabledRateLimiter(2)
	result, err := transport.CheckRateLimit(
		t.Context(),
		limiter,
		rateLimitContext("https://example.com/get-session?nonce=one"),
	)
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
	ctx := rateLimitContext("https://example.com/get-session")
	transport.WriteRateLimit(ctx, 7)
	if got := ctx.Response.StatusCode(); got != fasthttpserver.StatusTooManyRequests {
		t.Fatalf("status = %d", got)
	}
	if got := string(ctx.Response.Header.Peek("X-Retry-After")); got != "7" {
		t.Fatalf("retry header = %q", got)
	}
	if got := string(ctx.Response.Header.ContentType()); got != "text/plain;charset=UTF-8" {
		t.Fatalf("content type = %q", got)
	}
	if got := string(ctx.Response.Body()); got != ratelimit.TooManyRequestsBody {
		t.Fatalf("body = %q", got)
	}
}

func TestRateLimitMiddlewareStopsBlockedRequest(t *testing.T) {
	limiter := enabledRateLimiter(1)
	nextCalls := 0
	handler := transport.RateLimitMiddleware(
		limiter,
		func(*fasthttpserver.RequestCtx) { nextCalls++ },
		nil,
	)

	first := rateLimitContext("https://example.com/get-session")
	handler(first)
	second := rateLimitContext("https://example.com/get-session")
	handler(second)
	if nextCalls != 1 {
		t.Fatalf("next calls = %d", nextCalls)
	}
	if got := second.Response.StatusCode(); got != fasthttpserver.StatusTooManyRequests {
		t.Fatalf("blocked status = %d", got)
	}
	if got := string(second.Response.Body()); got != ratelimit.TooManyRequestsBody {
		t.Fatalf("blocked body = %q", got)
	}
}
